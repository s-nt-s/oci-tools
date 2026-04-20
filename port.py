from typing import NamedTuple, Optional
import sys
import json
import re
from datetime import datetime
from os import environ
from textwrap import dedent
from http.client import HTTPConnection
from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
from oci.core import ComputeClient, VirtualNetworkClient
from oci.response import Response
from oci.core.models.vnic_attachment import VnicAttachment
from oci.core.models.vnic import Vnic
from oci.core.models.subnet import Subnet
from oci.core.models.ingress_security_rule import IngressSecurityRule
from oci.core.models.security_list import SecurityList
from oci.core.models.tcp_options import TcpOptions
from oci.core.models.udp_options import UdpOptions
from oci.core.models.icmp_options import IcmpOptions
from oci.core.models.port_range import PortRange
from oci.core.models import UpdateSecurityListDetails

import logging

logger = logging.getLogger(__name__)

DEF_SOURCE = '0.0.0.0/0'
DEF_PROTO = 'TCP'


class SetRule(NamedTuple):
    source: str
    proto: str
    port: int
    description: Optional[str] = None


class PortRangeWrapper:
    def __init__(self, range: PortRange):
        self.__range = range

    def order_key(self):
        return (self.__range.min, self.__range.max)

    def __str__(self):
        if self.__range.min == self.__range.max:
            return f"{self.__range.min:4d}"
        return f"{self.__range.min}-{self.__range.max}"

    def is_in(self, port: int):
        return port in range(self.__range.min, self.__range.max+1)

    def is_eq(self, port: int):
        if self.__range.min != self.__range.max:
            return False
        return self.__range.min == port


class RuleWrapper:
    def __init__(self, rule: IngressSecurityRule, security_list_id: str):
        self.__rule = rule
        self.__security_list_id = security_list_id

    def __str__(self):
        msg: list[str] = []
        msg.append(self.source)
        msg.append(self.protocol)
        if self.destination_port:
            if self.source_port:
                msg.append(f"{self.source_port}->{self.destination_port}")
            else:
                msg.append(str(self.destination_port))
        if self.description:
            msg.append(self.description)
        return " ".join(msg)

    @property
    def rule(self) -> IngressSecurityRule:
        return self.__rule

    @property
    def security_list_id(self) -> str:
        return self.__security_list_id

    @property
    def source(self) -> str:
        return self.__rule.source

    @property
    def protocol(self) -> str:
        return {
            "1": "ICMP",
            "6": "TCP",
            "17": "UDP",
            "58": "ICMPv6",
            "all": "ALL"
        }.get(self.__rule.protocol, self.__rule.protocol)

    @property
    def tcp_options(self) -> TcpOptions | None:
        if self.__rule.protocol == "6":
            return self.__rule.tcp_options
        return None

    @property
    def udp_options(self) -> UdpOptions | None:
        if self.__rule.protocol == "17":
            return self.__rule.udp_options
        return None

    @property
    def icmp_options(self) -> IcmpOptions | None:
        if self.__rule.protocol == "1":
            return self.__rule.icmp_options
        return None

    def __get_options(self):
        for o in (
            self.icmp_options,
            self.udp_options,
            self.tcp_options
        ):
            if o is not None:
                return o
        return None

    @property
    def description(self) -> str:
        return self.__rule.description or ''

    @property
    def destination_port(self):
        opt = self.__get_options()
        if not isinstance(opt, (TcpOptions, UdpOptions)):
            return None
        port_range: Optional[PortRange] = opt.destination_port_range
        if port_range is None:
            return None
        return PortRangeWrapper(port_range)

    @property
    def source_port(self):
        opt = self.__get_options()
        if not isinstance(opt, (TcpOptions, UdpOptions)):
            return None
        port_range: Optional[PortRange] = opt.source_port_range
        if port_range is None:
            return None
        return PortRangeWrapper(port_range)

    def order_key(self):
        arr = []
        arr.append(self.source or '')
        arr.append(self.protocol or '')
        if self.destination_port:
            arr.append(self.destination_port.order_key())
        else:
            arr.append((0, 0))
        return tuple(arr)


class LocalMachine:
    def __init__(self):
        self.__instance_info = self.__get_instance_info()
        _signer = InstancePrincipalsSecurityTokenSigner()
        self.__compute_client = ComputeClient(
            config={},
            signer=_signer
        )
        self.__virtual_network_client = VirtualNetworkClient(
            config={},
            signer=_signer
        )

    @property
    def user_machine(self):
        u = environ['USER']
        return f"{u}@{self.id}"

    @property
    def id(self) -> str:
        return self.__instance_info['id']

    @property
    def compartmentId(self) -> str:
        return self.__instance_info['compartmentId']

    @property
    def name(self) -> str:
        return self.__instance_info['displayName']

    @property
    def region(self) -> str:
        return self.__instance_info['canonicalRegionName']

    def __get_instance_info(self):
        ERROR_MSG = "Error al obtener el OCID de la instancia"
        conn = HTTPConnection("169.254.169.254")
        conn.request(
            "GET",
            "/opc/v2/instance/",
            headers={"Authorization": "Bearer Oracle"}
        )
        body = conn.getresponse().read().decode()
        if not isinstance(body, str):
            raise Exception(ERROR_MSG)
        data = json.loads(body)
        if not isinstance(data, dict) or 'id' not in data:
            raise Exception(ERROR_MSG)
        return data

    def get_vnic_attachments(self) -> tuple[VnicAttachment, ...]:
        r: Response = self.__compute_client.list_vnic_attachments(
            instance_id=self.id,
            compartment_id=self.compartmentId
        )
        data: tuple[VnicAttachment, ...] = tuple(r.data)
        return data

    def get_security_list_ids(self):
        all_security_list_ids: set[str] = set()

        for vnic_attachment in self.get_vnic_attachments():
            vnic_details: Vnic = self.__virtual_network_client.get_vnic(vnic_attachment.vnic_id).data
            subnet_details: Subnet = self.__virtual_network_client.get_subnet(vnic_details.subnet_id).data
            if subnet_details.security_list_ids:
                all_security_list_ids.update(subnet_details.security_list_ids)

        return tuple(sorted(all_security_list_ids))

    def iter_ingress_rules(self):
        for sl_id in self.get_security_list_ids():
            for rule in self.__get_ingress_security_list(sl_id):
                yield RuleWrapper(
                    rule,
                    sl_id
                )

    def __get_security_list(self, security_list_id: str):
        security_list = self.__virtual_network_client.get_security_list(security_list_id).data
        if security_list is None:
            return None
        if not isinstance(security_list, SecurityList):
            raise ValueError(f"Expected security_rules to be a SecurityList, got {type(security_list)}")
        return security_list

    def __get_ingress_security_list(self, security_list_id: str, avoid: tuple[IngressSecurityRule, ...] = tuple()) -> list[IngressSecurityRule]:
        security_list: SecurityList = self.__get_security_list(security_list_id)
        if security_list is None or security_list.ingress_security_rules is None:
            return tuple()
        if not isinstance(security_list.ingress_security_rules, list):
            raise ValueError(f"Expected ingress_security_rules to be a list, got {type(security_list.ingress_security_rules)}")
        ingress_security_rules = list(security_list.ingress_security_rules)
        for a in avoid:
            ingress_security_rules.remove(a)
        return ingress_security_rules

    def __update_security_list(self, security_list_id: str, updated_rules: list[IngressSecurityRule]):
        self.__virtual_network_client.update_security_list(
            security_list_id,
            UpdateSecurityListDetails(
                ingress_security_rules=updated_rules
            )
        )

    def set_rules(self, *rules: SetRule):
        for r in rules:
            if r.port < 0:
                self.del_rule(r._replace(port=abs(r.port)))
        for r in rules:
            if r.port > 0:
                self.add_rule(r)

    def __find_rule(self, rule: SetRule):
        ok: list[RuleWrapper] = []
        ko: list[RuleWrapper] = []
        for r in self.iter_ingress_rules():
            if r.protocol != rule.proto or r.destination_port is None:
                continue
            if not r.destination_port.is_in(rule.port):
                continue
            if r.source_port is None and r.destination_port.is_eq(rule.port) and r.source == rule.source:
                ok.append(r)
                continue
            ko.append(r)
        if len(ok) == 0:
            return None, tuple(ko)
        if len(ok) > 1:
            return None, tuple(ok + ko)
        return ok[0], tuple(ko)

    def del_rule(self, rm: SetRule):
        ok, ko = self.__find_rule(rm)
        if ko:
            for r in ko:
                logger.error(f"Conflicto con {r}")
            return
        if ok:
            self.__del_rule(ok)

    def add_rule(self, nw: SetRule):
        ok, ko = self.__find_rule(nw)
        if ko:
            for r in ko:
                logger.error(f"Conflicto con {r}")
            return
        if ok is None:
            self.__add_rule(nw) 
        elif nw.description and ok.description != nw.description:
            self.__set_description(ok, nw.description)

    def __del_rule(self, r: RuleWrapper):
        updated_rules = self.__get_ingress_security_list(
            r.security_list_id,
            avoid=(r.rule, )
        )

        self.__update_security_list(
            r.security_list_id,
            updated_rules
        )

    def __add_rule(self, nw: SetRule):
        if nw.proto not in ("TCP", "UDP"):
            raise NotImplementedError(nw.proto)
        if nw.description is None:
            nw = nw._replace(
                description="Created {dt:%Y-%m-%d %H:%M} by {lb}".format(dt=datetime.now(), lb=self.user_machine)
            )
        security_list_ids = self.get_security_list_ids()
        if not security_list_ids:
            logger.error("No security lists found to add rule")
            return
        security_list_id = security_list_ids[0]
        updated_rules = self.__get_ingress_security_list(
            security_list_id,
        )
        new_rule = IngressSecurityRule(
            source=nw.source,
            protocol="6" if nw.proto == "TCP" else "17",
            description=nw.description,
            is_stateless=False
        )

        port_range = PortRange(min=nw.port, max=nw.port)
        if nw.proto == "TCP":
            new_rule.tcp_options = TcpOptions(destination_port_range=port_range)
        elif nw.proto == "UDP":
            new_rule.udp_options = UdpOptions(destination_port_range=port_range)

        updated_rules.append(new_rule)
        self.__update_security_list(
            security_list_id,
            updated_rules,
        )

    def __set_description(self, r: RuleWrapper, description: str):
        if r.description == description:
            return
        updated_rules = self.__get_ingress_security_list(
            r.security_list_id,
            avoid=(r.rule, )
        )
        r.rule.description = description
        updated_rules.append(r.rule)

        self.__update_security_list(
            r.security_list_id,
            updated_rules
        )


def parse_args(
        *args: str
    ) -> tuple[SetRule, ...]:
    if len(args) == 0:
        return tuple()
    source: set[str] = set()
    ports: set[int] = set()
    proto: set[str] = set()
    description: list[str] = []
    for a in args:
        if len(description):
            description.append(a)
            continue
        if re.match(r"^[\-\+]?\d+$", a):
            ports.add(int(a))
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", a):
            source.add(a)
            continue
        if re.match(r"^(TCP|UDP)$", a, flags=re.I):
            proto.add(a.upper())
        description.append(a)
    if 0 in ports:
        logger.warning("Puerto 0 descargado por invalido")
        ports.discard(0)
    if len(proto) == 0:
        logger.debug(f"Se usará {DEF_PROTO} como protocolo por defecto")
        proto.add(DEF_PROTO)
    if len(source) == 0:
        logger.debug(f"Se usará {DEF_SOURCE} como origen por defecto")
        source.add(DEF_SOURCE)
    error = False
    if len(ports) == 0:
        logger.error("Debe pasar al menos un puerto valido como parámetro")
        error = True
    for lb, st in {
        "origen": source,
        "protocolo": proto
    }.items():
        if len(st) != 1:
            logger.error(f"Debe pasar exactamente un {lb} como parámetro")
            error = True
    if error:
        sys.exit(1)
    template = SetRule(
        source=source.pop(),
        proto=proto.pop(),
        port=0,
        description=" ".join(description) if description else None
    )
    rules: list[SetRule] = []
    for p in sorted(ports):
        rules.append(template._replace(port=p))
    return tuple(rules)


def print_help():
    print(dedent('''
    Lista, añade o elimina puertos del security list para acceder a esta máquina.

    Argumentos:
    * --help o -h: Muestra esta ayuda y sale
    * Ninguno: Muestra la lista actual de puertos y sale
    * Para realizar modificaciones:
        * puerto/s (obligatorio):
            * un número positivo si se ha de añadir la regla o modificar la descripción de la regla
            * un número negativo si se ha de eliminar la regla
        * protocolo: TCP o UDP, por defecto {proto}
        * origen: IP o CIDR de origen, por defecto {source}
        * descripción: descripción de la regla, por defecto fecha de creación y autor
        * Los argumentos pueden estar en cualquier orden excepto la descripción, que ha de ser el último

    Tras realizar las medicaciones con éxito se muestra la lista actual de puertos.
    ''').strip().format(proto=DEF_PROTO, source=DEF_SOURCE))


if __name__ == "__main__":
    args = sys.argv[1:]
    if set(args).intersection({
        "--help",
        "-h"
    }):
        print_help()
        sys.exit(0)

    logging.basicConfig(
        format="%(message)s",
        level=logging.INFO
    )

    rules = parse_args(
        *args
    )
    LOCAL_MACHINE = LocalMachine()
    LOCAL_MACHINE.set_rules(*rules)

    last_source = None
    for w in sorted(LOCAL_MACHINE.iter_ingress_rules(), key=lambda x: x.order_key()):
        if w.source != last_source:
            print(w.source)
        print("", str(w).split(None, 1)[-1])
        last_source = w.source