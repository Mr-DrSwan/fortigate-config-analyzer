#!/usr/bin/env python3
"""
FortiGate Config Parser - Чистый и рабочий
Парсит конфигурацию и создает Excel с листами:
1. Локальные пользователи
2. Правила фаервола (ВСЕ поля)
3. IPSec туннели
4. Статические маршруты
5. NAT правила
6. Адреса
7. VPN пользователи
"""

import pandas as pd
import ipaddress
import time
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Set, Tuple
import sys
import os


class FortigateConfigParser:
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config_data = self._read_config()
        self._lines = self.config_data.splitlines()
        self._section_ranges = self._build_section_ranges()
        self.dataframes = {}
        self.address_objects: Dict[str, Dict[str, str]] = {}
        self.address_group_objects: Dict[str, Dict[str, str]] = {}
        self.address_group_members: Dict[str, List[str]] = {}
        self.address_entries: List[Dict[str, str]] = []
        self._user_group_blocks: Optional[List[Dict[str, str]]] = None
        self.profile: Dict[str, float] = {}

        # Словарь переводов полей firewall
        self.firewall_translations = {
            'policyid': 'ID',
            'name': 'Имя_правила',
            'uuid': 'UUID',
            'srcintf': 'Входящий_интерфейс',
            'dstintf': 'Исходящий_интерфейс',
            'action': 'Действие',
            'srcaddr': 'Источник',
            'dstaddr': 'Назначение',
            'schedule': 'Расписание',
            'service': 'Сервис',
            'users': 'Пользователи',
            'groups': 'Группы',
            'nat': 'NAT',
            'status': 'Статус',
            'comments': 'Описание',
            'utm-status': 'UTM_статус',
            'ssl-ssh-profile': 'SSL_SSH_профиль',
            'webfilter-profile': 'Веб_фильтр',
            'ips-sensor': 'IPS_сенсор',
            'application-list': 'Список_приложений',
            'av-profile': 'Антивирус',
            'logtraffic': 'Логирование',
            'logtraffic-start': 'Логирование_начала',
            'capture-packet': 'Захват_пакетов',
            'schedule': 'Расписание',
            'internet-service': 'Интернет_сервис',
            'internet-service-src': 'Источник_интернет_сервиса',
            'tcp-mss-sender': 'TCP_MSS_отправитель',
            'tcp-mss-receiver': 'TCP_MSS_получатель',
            'permit-any-host': 'Разрешить_любой_хост',
            'permit-stun-host': 'Разрешить_STUN_хост',
            'block-notification': 'Уведомление_блокировки',
            'replacemsg-override-group': 'Группа_сообщений',
            'disclaimer': 'Отказ',
            'vlan-cos-fwd': 'VLAN_COS_вперед',
            'vlan-cos-rev': 'VLAN_COS_назад',
            'vlan-filter': 'Фильтр_VLAN',
            'rtp-nat': 'RTP_NAT',
            'rtp-addr': 'Адрес_RTP',
            'session-ttl': 'TTL_сессии',
            'learning-mode': 'Режим_обучения',
            'ssh-policy-redirect': 'Перенаправление_SSH',
            'ssh-filter-profile': 'Профиль_SSH_фильтра',
            'profile-protocol-options': 'Опции_протокола',
            'profile-group': 'Группа_профилей',
            'scan-botnet-connections': 'Сканирование_Botnet',
            'dsri': 'DSRI',
            'radius-mac-auth-bypass': 'Обход_RADIUS_MAC',
            'delay-tcp-npu-session': 'Задержка_TCP_NPU',
            'diffserv-forward': 'DiffServ_вперед',
            'diffserv-reverse': 'DiffServ_назад',
            'tcp-session-without-syn': 'TCP_сессия_без_SYN',
            'geoip-anycast': 'GeoIP_Anycast',
            'match-vip': 'Совпадение_VIP',
            'match-vip-only': 'Только_совпадение_VIP',
            'np-acceleration': 'NP_ускорение',
            'ztna-status': 'Статус_ZTNA',
            'ztna-ems-tag': 'Тег_ZTNA_EMS',
            'ztna-geo-tag': 'Тег_ZTNA_гео',
            'wsso': 'WSSO',
            'fsso': 'FSSO',
            'rsso': 'RSSO',
            'ntlm': 'NTLM',
            'ntlm-enabled-browsers': 'Браузеры_NTLM',
            'ntlm-guest': 'Гость_NTLM',
            'custom-log-fields': 'Поля_лога',
            'traffic-shaper': 'Шейпер_трафика',
            'traffic-shaper-reverse': 'Шейпер_обратный',
            'per-ip-shaper': 'Шейпер_на_IP',
            'application': 'Приложение',
            'app-category': 'Категория_приложений',
            'url-category': 'Категория_URL',
            'app-group': 'Группа_приложений',
            'voip-profile': 'Профиль_VoIP',
            'waf-profile': 'Профиль_WAF',
            'dnsfilter-profile': 'Профиль_DNS_фильтра',
            'emailfilter-profile': 'Профиль_фильтра_почты',
            'dlp-sensor': 'Сенсор_DLP',
            'file-filter-profile': 'Профиль_фильтра_файлов',
            'icap-profile': 'Профиль_ICAP',
            'cifs-profile': 'Профиль_CIFS',
            'videofilter-profile': 'Профиль_видеофильтра',
            'ssh-filter-profile': 'Профиль_SSH_фильтра',
            'profile-protocol-options': 'Опции_протокола',
            'ssl-mirror': 'SSL_зеркалирование',
            'ssl-mirror-intf': 'Интерфейс_SSL_зеркалирования',
            'wanopt': 'WAN_оптимизация',
            'wanopt-detection': 'Обнаружение_WAN_оптимизации',
            'wanopt-passive-opt': 'Пассивная_оптимизация_WAN',
            'wanopt-peer': 'Пир_WAN_оптимизации',
            'wanopt-profile': 'Профиль_WAN_оптимизации',
            'webcache': 'Веб_кэш',
            'webcache-https': 'Веб_кэш_HTTPS',
            'webproxy-forward-server': 'Прямой_сервер_прокси',
            'webproxy-profile': 'Профиль_веб_прокси',
            'ztna-ems-tag': 'Тег_ZTNA_EMS',
            'ztna-geo-tag': 'Тег_ZTNA_гео',
        }

    def _read_config(self) -> str:
        """Чтение файла конфигурации"""
        try:
            with open(self.config_file, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except FileNotFoundError:
            print(f"❌ Файл не найден: {self.config_file}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Ошибка чтения файла: {e}")
            sys.exit(1)

    def _build_section_ranges(self) -> Dict[str, List[Tuple[int, int]]]:
        ranges: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        depth = 0
        current_name: Optional[str] = None
        current_start = -1
        for idx, raw_line in enumerate(self._lines):
            line = raw_line.strip()
            if not line:
                continue
            lower = line.lower()
            if lower.startswith("config "):
                if depth == 0:
                    current_name = lower[len("config "):].strip()
                    current_start = idx + 1
                depth += 1
                continue
            if lower == "end" and depth > 0:
                depth -= 1
                if depth == 0 and current_name is not None and current_start >= 0:
                    ranges[current_name].append((current_start, idx))
                    current_name = None
                    current_start = -1
        return ranges

    @staticmethod
    def _parse_set_value(raw_value: str) -> str:
        value = raw_value.strip()
        if '"' not in value:
            if value.startswith('"') and value.endswith('"'):
                return value[1:-1]
            return value
        extracted: List[str] = []
        in_quotes = False
        current: List[str] = []
        for char in value:
            if char == '"':
                if in_quotes:
                    extracted.append("".join(current))
                    current = []
                    in_quotes = False
                else:
                    in_quotes = True
                continue
            if in_quotes:
                current.append(char)
        if extracted:
            return " ".join(extracted)
        return value

    def _extract_blocks(self, block_name: str) -> List[Dict]:
        """Извлекает все edit/next блоки из нужного config-раздела."""
        target = block_name.lower().strip()
        ranges = self._section_ranges.get(target, [])
        all_blocks: List[Dict] = []
        for start_idx, end_idx in ranges:
            config_depth = 1
            current_block: Optional[Dict[str, str]] = None
            for raw_line in self._lines[start_idx:end_idx]:
                line = raw_line.strip()
                if not line:
                    continue
                lower = line.lower()
                if lower.startswith("config "):
                    config_depth += 1
                    continue
                if lower == "end":
                    if config_depth > 1:
                        config_depth -= 1
                    continue
                if config_depth != 1:
                    continue
                if lower.startswith("edit "):
                    if current_block is not None:
                        all_blocks.append(current_block)
                    edit_value = line[5:].strip()
                    if edit_value.startswith('"') and edit_value.endswith('"'):
                        edit_value = edit_value[1:-1]
                    current_block = {"_name": edit_value}
                    continue
                if lower == "next":
                    if current_block is not None:
                        all_blocks.append(current_block)
                        current_block = None
                    continue
                if lower.startswith("set ") and current_block is not None:
                    parts = line.split(maxsplit=2)
                    if len(parts) < 2:
                        continue
                    param = parts[1]
                    raw_value = parts[2] if len(parts) > 2 else ""
                    current_block[param] = self._parse_set_value(raw_value)
            if current_block is not None:
                all_blocks.append(current_block)

        return all_blocks

    @staticmethod
    def _split_members(value: str) -> List[str]:
        """Split FortiGate member list into object names."""
        if not value:
            return []
        return [item for item in value.split() if item]

    @staticmethod
    def parse_existing_object_names(cli_output: str) -> Set[str]:
        """Parse `edit ...` object names from FortiGate CLI output."""
        names: Set[str] = set()
        for raw_line in cli_output.splitlines():
            line = raw_line.strip()
            if not line.lower().startswith("edit "):
                continue
            value = line[5:].strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            if value:
                names.add(value)
        return names

    @staticmethod
    def _quote(value: str) -> str:
        escaped = value.replace('"', r'\"')
        return f'"{escaped}"'

    def _format_set_value(self, key: str, value: str) -> str:
        if key == "member":
            members = self._split_members(value)
            return " ".join(self._quote(member) for member in members)
        if key in {"subnet", "iprange"}:
            return value
        if key in {"comment", "comments", "fqdn", "interface", "associated-interface"}:
            return self._quote(value)
        if " " in value:
            return self._quote(value)
        return value

    def _build_address_command_block(self, name: str, color_override: Optional[int] = None) -> List[str]:
        obj = dict(self.address_objects.get(name, {}))
        if color_override is not None:
            obj["color"] = str(color_override)
        lines = [f'    edit {self._quote(name)}']
        for key, value in obj.items():
            if key in {"_name", "uuid", "associated-interface"}:
                continue
            if value == "":
                continue
            lines.append(f"        set {key} {self._format_set_value(key, value)}")
        lines.append("    next")
        return lines

    def _build_addrgrp_command_block(self, name: str, color_override: Optional[int] = None) -> List[str]:
        obj = dict(self.address_group_objects.get(name, {}))
        if color_override is not None:
            obj["color"] = str(color_override)
        lines = [f'    edit {self._quote(name)}']
        for key, value in obj.items():
            if key in {"_name", "uuid"}:
                continue
            if value == "":
                continue
            lines.append(f"        set {key} {self._format_set_value(key, value)}")
        lines.append("    next")
        return lines

    @staticmethod
    def _normalize_whitespace(value: str) -> str:
        return " ".join(value.split())

    def _extract_address_value_signature(self, obj: Dict[str, str]) -> tuple[str, str]:
        fqdn = self._normalize_whitespace(obj.get("fqdn", ""))
        if fqdn:
            return "fqdn", fqdn.lower()

        iprange = self._normalize_whitespace(obj.get("iprange", ""))
        if iprange:
            return "iprange", iprange

        subnet = self._normalize_whitespace(obj.get("subnet", ""))
        if subnet:
            parts = subnet.split()
            if len(parts) == 2:
                try:
                    network = ipaddress.IPv4Network((parts[0], parts[1]), strict=False)
                    return "subnet", f"{network.network_address}/{network.prefixlen}"
                except ValueError:
                    pass
            return "subnet", subnet

        wildcard = self._normalize_whitespace(obj.get("wildcard", ""))
        if wildcard:
            return "wildcard", wildcard

        start_ip = self._normalize_whitespace(obj.get("start-ip", ""))
        end_ip = self._normalize_whitespace(obj.get("end-ip", ""))
        if start_ip or end_ip:
            return "range", f"{start_ip}-{end_ip}"

        relevant_items = []
        for key in sorted(obj):
            if key in {"_name", "uuid", "comment", "comments", "color", "associated-interface"}:
                continue
            value = self._normalize_whitespace(obj.get(key, ""))
            if value:
                relevant_items.append(f"{key}={value}")
        return "other", ";".join(relevant_items)

    def find_duplicate_addresses(self) -> Dict[str, object]:
        """Find duplicates inside firewall address config section."""
        entries = self.address_entries
        if not entries:
            entries = self._extract_blocks("firewall address")
            self.address_entries = entries

        by_value: Dict[tuple[str, str], List[str]] = {}
        by_name: Dict[str, List[Dict[str, str]]] = {}
        exact_records: Dict[tuple[str, str], int] = {}

        for obj in entries:
            name = obj.get("_name", "").strip()
            if not name:
                continue
            value_sig = self._extract_address_value_signature(obj)
            by_value.setdefault(value_sig, []).append(name)
            by_name.setdefault(name, []).append(obj)

            payload_items = []
            for key in sorted(obj):
                if key in {"uuid"}:
                    continue
                payload_items.append(f"{key}={self._normalize_whitespace(str(obj.get(key, '')))}")
            record_key = (name, "|".join(payload_items))
            exact_records[record_key] = exact_records.get(record_key, 0) + 1

        same_value_different_names: List[Dict[str, object]] = []
        for (value_type, value), names in by_value.items():
            unique_names = sorted(set(names))
            if len(unique_names) > 1:
                same_value_different_names.append(
                    {
                        "value_type": value_type,
                        "value": value,
                        "names": unique_names,
                    }
                )

        same_name_multiple_entries: List[Dict[str, object]] = []
        for name, objs in by_name.items():
            if len(objs) <= 1:
                continue
            signatures = sorted({self._extract_address_value_signature(obj)[1] for obj in objs})
            same_name_multiple_entries.append(
                {
                    "name": name,
                    "count": len(objs),
                    "values": signatures,
                }
            )

        exact_duplicate_entries: List[Dict[str, object]] = []
        for (name, payload), count in exact_records.items():
            if count > 1:
                exact_duplicate_entries.append({"name": name, "count": count})

        same_value_different_names.sort(key=lambda item: (str(item["value"]), ",".join(item["names"])))
        same_name_multiple_entries.sort(key=lambda item: str(item["name"]).lower())
        exact_duplicate_entries.sort(key=lambda item: str(item["name"]).lower())

        return {
            "total_entries": len([obj for obj in entries if obj.get("_name", "").strip()]),
            "same_value_different_names": same_value_different_names,
            "same_name_multiple_entries": same_name_multiple_entries,
            "exact_duplicate_entries": exact_duplicate_entries,
        }

    def build_transfer_plan(
        self,
        selected_addresses: Set[str],
        selected_groups: Set[str],
        existing_names: Set[str],
        group_color_overrides: Optional[Dict[str, int]] = None,
        address_color_overrides: Optional[Dict[str, int]] = None,
    ) -> Dict[str, object]:
        """Build transfer command plan while skipping duplicates on target."""
        group_color_overrides = group_color_overrides or {}
        address_color_overrides = address_color_overrides or {}
        expanded_group_members: Set[str] = set()
        for group_name in selected_groups:
            expanded_group_members.update(self.address_group_members.get(group_name, []))

        effective_addresses = set(selected_addresses) | expanded_group_members
        duplicate_addresses = sorted(name for name in effective_addresses if name in existing_names)
        duplicate_groups = sorted(name for name in selected_groups if name in existing_names)

        addresses_to_create = sorted(name for name in effective_addresses if name not in existing_names)
        groups_to_create = sorted(name for name in selected_groups if name not in existing_names)

        command_lines: List[str] = []
        if addresses_to_create:
            command_lines.append("config firewall address")
            for name in addresses_to_create:
                command_lines.extend(self._build_address_command_block(name, address_color_overrides.get(name)))
            command_lines.append("end")
            command_lines.append("")

        # If address already exists on target, still allow explicit color update when user provided override.
        existing_addresses_to_recolor = sorted(
            name for name in duplicate_addresses if name in address_color_overrides
        )
        if existing_addresses_to_recolor:
            command_lines.append("# Обновление цвета существующих адресов")
            command_lines.append("config firewall address")
            for name in existing_addresses_to_recolor:
                command_lines.append(f'    edit {self._quote(name)}')
                command_lines.append(f"        set color {address_color_overrides[name]}")
                command_lines.append("    next")
            command_lines.append("end")
            command_lines.append("")

        if groups_to_create:
            command_lines.append("config firewall addrgrp")
            for name in groups_to_create:
                command_lines.extend(self._build_addrgrp_command_block(name, group_color_overrides.get(name)))
            command_lines.append("end")

        if not command_lines:
            command_lines = ["# Все выбранные объекты уже существуют на целевом FortiGate."]

        return {
            "duplicate_addresses": duplicate_addresses,
            "duplicate_groups": duplicate_groups,
            "addresses_to_create": addresses_to_create,
            "groups_to_create": groups_to_create,
            "commands_text": "\n".join(command_lines).strip(),
        }

    def parse_local_users(self):
        """Парсит локальных пользователей"""
        print("👥 Парсинг локальных пользователей...")
        users = self._extract_blocks('user local')

        data = []
        for idx, user in enumerate(users, 1):
            data.append({
                '№': idx,
                'Имя': user.get('_name', ''),
                'Тип': user.get('type', ''),
                'Роль': user.get('accprofile', user.get('user-type', '')),
                'Группы': user.get('member', ''),
                'Email': user.get('email', ''),
                'Телефон': user.get('mobile-phone', user.get('phone', '')),
                '2FA': 'Да' if user.get('two-factor') == 'enable' else 'Нет',
                'Статус': 'Активен' if user.get('status') != 'disable' else 'Отключен',
                'Срок': user.get('expire', ''),
                'Комментарий': user.get('comments', '')
            })

        self.dataframes['Локальные_пользователи'] = pd.DataFrame(data)
        print(f"   Найдено: {len(data)}")

    def parse_user_groups(self):
        """Парсит группы пользователей"""
        print("👥 Парсинг групп пользователей...")
        groups = self._extract_blocks('user group')
        self._user_group_blocks = groups

        data = []
        for idx, group in enumerate(groups, 1):
            data.append({
                '№': idx,
                'Имя_группы': group.get('_name', ''),
                'Тип': group.get('type', ''),
                'Члены': group.get('member', ''),
                'Комментарий': group.get('comments', '')
            })

        self.dataframes['Группы_пользователей'] = pd.DataFrame(data)
        print(f"   Найдено: {len(data)}")

    def parse_firewall_rules(self):
        """Парсит правила фаервола со ВСЕМИ полями"""
        print("🔥 Парсинг правил фаервола...")
        rules = self._extract_blocks('firewall policy')

        if not rules:
            self.dataframes['Firewall_правила'] = pd.DataFrame()
            print("   Не найдено")
            return

        data = []
        all_fields: Set[str] = set()
        for idx, rule in enumerate(rules, 1):
            row = {'№': idx}
            for field, raw_value in rule.items():
                all_fields.add(field)
                # Переводим имя поля
                russian_field = self.firewall_translations.get(field, field)

                # Получаем значение
                value = raw_value

                # Специальная обработка для некоторых полей
                if field == 'action':
                    action_map = {
                        'accept': 'Разрешить',
                        'deny': 'Запретить',
                        'ipsec': 'IPSec',
                        'ssl-vpn': 'SSL-VPN'
                    }
                    value = action_map.get(value, value)
                elif field == 'status':
                    value = 'Включено' if value != 'disable' else 'Выключено'
                elif field == 'nat':
                    value = 'Включен' if value == 'enable' else 'Выключен'
                elif field == 'logtraffic':
                    log_map = {
                        'all': 'Всё',
                        'utm': 'UTM',
                        'disable': 'Отключено',
                        'enable': 'Включено'
                    }
                    value = log_map.get(value, value)
                elif field == 'utm-status':
                    value = 'Включен' if value == 'enable' else 'Выключен'

                row[russian_field] = value

            data.append(row)

        df = pd.DataFrame(data)

        # Определяем порядок столбцов: сначала важные
        important_cols = ['№', 'ID', 'Имя_правила', 'UUID', 'Входящий_интерфейс',
                          'Исходящий_интерфейс', 'Действие', 'Источник', 'Назначение',
                          'Сервис', 'Пользователи', 'Группы', 'Статус', 'NAT',
                          'Логирование', 'UTM_статус', 'Расписание', 'Описание']

        # Сортируем остальные столбцы алфавитно
        other_cols = sorted([col for col in df.columns if col not in important_cols])

        # Фильтруем только существующие колонки
        existing_important = [col for col in important_cols if col in df.columns]

        # Собираем финальный порядок
        final_order = existing_important + other_cols

        self.dataframes['Firewall_правила'] = df[final_order]
        print(f"   Найдено: {len(rules)} правил, {len(all_fields)} уникальных полей")

    def parse_ipsec_tunnels(self):
        """Парсит IPSec туннели"""
        print("🔐 Парсинг IPSec туннелей...")
        tunnels = self._extract_blocks('vpn ipsec phase1-interface')

        data = []
        for idx, tunnel in enumerate(tunnels, 1):
            data.append({
                '№': idx,
                'Имя_туннеля': tunnel.get('_name', ''),
                'Локальный_шлюз': tunnel.get('local-gw', ''),
                'Удаленный_шлюз': tunnel.get('remote-gw', ''),
                'Интерфейс': tunnel.get('interface', ''),
                'Протокол': tunnel.get('type', ''),
                'Шифрование': tunnel.get('proposal', ''),
                'Аутентификация': tunnel.get('authmethod', ''),
                'PSK': 'Да' if tunnel.get('psksecret') else 'Нет',
                'Статус': 'Активен' if tunnel.get('status') != 'disable' else 'Отключен',
                'Комментарий': tunnel.get('comments', '')
            })

        self.dataframes['IPSec_Туннели'] = pd.DataFrame(data)
        print(f"   Найдено: {len(data)}")

    def parse_static_routes(self):
        """Парсит статические маршруты"""
        print("🛣️  Парсинг статических маршрутов...")
        routes = self._extract_blocks('router static')

        data = []
        for idx, route in enumerate(routes, 1):
            dst = route.get('dst', '').split()

            data.append({
                '№': idx,
                'Сеть_назначения': dst[0] if len(dst) > 0 else '',
                'Маска': dst[1] if len(dst) > 1 else '',
                'Шлюз': route.get('gateway', ''),
                'Интерфейс': route.get('device', ''),
                'Дистанция': route.get('distance', ''),
                'Приоритет': route.get('priority', ''),
                'Комментарий': route.get('comments', '')
            })

        self.dataframes['Статические_маршруты'] = pd.DataFrame(data)
        print(f"   Найдено: {len(data)}")

    def parse_nat_rules(self):
        """Парсит NAT правила"""
        print("🔄 Парсинг NAT правил...")
        nats = self._extract_blocks('firewall vip')

        data = []
        for idx, nat in enumerate(nats, 1):
            data.append({
                '№': idx,
                'Тип': 'Port Forward' if nat.get('portforward') == 'enable' else 'VIP',
                'Имя': nat.get('_name', ''),
                'Внешний_IP': nat.get('extip', ''),
                'Внешний_порт': nat.get('extport', ''),
                'Внутренний_IP': nat.get('mappedip', ''),
                'Внутренний_порт': nat.get('mappedport', ''),
                'Протокол': nat.get('protocol', ''),
                'Интерфейс': nat.get('extintf', ''),
                'Статус': 'Активен' if nat.get('status') != 'disable' else 'Отключен',
                'Комментарий': nat.get('comments', '')
            })

        self.dataframes['NAT_правила'] = pd.DataFrame(data)
        print(f"   Найдено: {len(data)}")

    def parse_addresses(self):
        """Парсит адреса и группы адресов в отдельные таблицы"""
        print("📍 Парсинг адресов...")
        addresses = self._extract_blocks('firewall address')
        self.address_entries = addresses
        addr_groups = self._extract_blocks('firewall addrgrp')
        self.address_objects = {addr.get("_name", ""): addr for addr in addresses if addr.get("_name")}
        self.address_group_objects = {grp.get("_name", ""): grp for grp in addr_groups if grp.get("_name")}

        # Map address -> groups where it is a member.
        address_to_groups: Dict[str, List[str]] = {}
        for group in addr_groups:
            group_name = group.get('_name', '')
            members = self._split_members(group.get('member', ''))
            self.address_group_members[group_name] = members
            for member in members:
                address_to_groups.setdefault(member, []).append(group_name)

        addresses_data = []
        for addr in addresses:
            name = addr.get('_name', '')
            groups = sorted(address_to_groups.get(name, []))
            iprange = addr.get('iprange', '')
            start_ip = ''
            end_ip = ''
            if iprange:
                parts = iprange.split()
                start_ip = parts[0] if len(parts) > 0 else ''
                end_ip = parts[1] if len(parts) > 1 else ''

            addresses_data.append({
                'name': name,
                'type': addr.get('type', ''),
                'subnet': addr.get('subnet', ''),
                'start-ip': start_ip,
                'end-ip': end_ip,
                'fqdn': addr.get('fqdn', ''),
                'comment': addr.get('comment', addr.get('comments', '')),
                'member-of': ' '.join(groups),
            })

        groups_data = []
        for group in addr_groups:
            groups_data.append({
                'name': group.get('_name', ''),
                'type': group.get('type', ''),
                'member': group.get('member', ''),
                'comment': group.get('comment', group.get('comments', '')),
            })

        self.dataframes['Адреса'] = pd.DataFrame(addresses_data)
        self.dataframes['Группы_адресов'] = pd.DataFrame(groups_data)
        print(f"   Адресов: {len(addresses_data)}, групп адресов: {len(groups_data)}")

    def parse_vpn_users(self):
        """Парсит VPN пользователей"""
        print("🔓 Парсинг VPN пользователей...")

        data = []

        # Пользователи peer
        peers = self._extract_blocks('user peer')
        for idx, peer in enumerate(peers, 1):
            data.append({
                '№': idx,
                'Тип': 'Peer пользователь',
                'Имя': peer.get('_name', ''),
                'Метод_аутентификации': peer.get('type', ''),
                'Пароль': 'Есть' if peer.get('passwd') else 'Нет',
                'Комментарий': peer.get('comments', '')
            })

        # Группы для VPN
        vpn_groups = self._user_group_blocks if self._user_group_blocks is not None else self._extract_blocks('user group')
        start_idx = len(data) + 1
        for idx, group in enumerate(vpn_groups, start_idx):
            if 'vpn' in group.get('_name', '').lower() or 'ssl' in group.get('_name', '').lower():
                data.append({
                    '№': idx,
                    'Тип': 'VPN группа',
                    'Имя': group.get('_name', ''),
                    'Метод_аутентификации': group.get('type', ''),
                    'Члены': group.get('member', ''),
                    'Комментарий': group.get('comments', '')
                })

        self.dataframes['VPN_Пользователи'] = pd.DataFrame(data)
        print(f"   Найдено: {len(data)}")

    def parse_all(self):
        """Парсит всю конфигурацию"""
        print("\n" + "=" * 70)
        print("🚀 НАЧИНАЮ ПАРСИНГ КОНФИГУРАЦИИ FORTIGATE")
        print("=" * 70)

        self.profile = {}

        def run_step(step_name: str, callback: Callable[[], None]) -> None:
            started = time.perf_counter()
            callback()
            self.profile[step_name] = time.perf_counter() - started

        run_step("parse_local_users", self.parse_local_users)
        run_step("parse_user_groups", self.parse_user_groups)
        run_step("parse_firewall_rules", self.parse_firewall_rules)
        run_step("parse_ipsec_tunnels", self.parse_ipsec_tunnels)
        run_step("parse_static_routes", self.parse_static_routes)
        run_step("parse_nat_rules", self.parse_nat_rules)
        run_step("parse_addresses", self.parse_addresses)
        run_step("parse_vpn_users", self.parse_vpn_users)

        print("\n✅ ПАРСИНГ ЗАВЕРШЕН!")

    def parse_addresses_only(self) -> None:
        started = time.perf_counter()
        self.parse_addresses()
        self.profile = {"parse_addresses_only": time.perf_counter() - started}

    @staticmethod
    def _sanitize_spreadsheet_cell(value):
        if not isinstance(value, str):
            return value
        if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + value
        return value

    def save_to_excel(self, filename: str = "fortigate_analysis.xlsx"):
        """Сохраняет все данные в Excel файл"""
        print(f"\n💾 Сохраняю в Excel: {filename}")

        if not self.dataframes:
            print("❌ Нет данных для сохранения")
            return

        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            # Порядок листов
            sheets_order = [
                'Локальные_пользователи',
                'Группы_пользователей',
                'Firewall_правила',
                'IPSec_Туннели',
                'Статические_маршруты',
                'NAT_правила',
                'Адреса',
                'Группы_адресов',
                'VPN_Пользователи'
            ]

            for sheet_name in sheets_order:
                if sheet_name in self.dataframes:
                    df = self.dataframes[sheet_name]
                    if not df.empty:
                        sanitized_df = df.copy()
                        for col_name in sanitized_df.columns:
                            if sanitized_df[col_name].dtype == object:
                                sanitized_df[col_name] = sanitized_df[col_name].map(self._sanitize_spreadsheet_cell)
                        # Сохраняем в Excel
                        sanitized_df.to_excel(writer, sheet_name=sheet_name, index=False)

                        # Настраиваем ширину столбцов
                        worksheet = writer.sheets[sheet_name]
                        max_rows_for_width = min(200, worksheet.max_row)
                        for column in worksheet.columns:
                            max_length = 0
                            column_letter = column[0].column_letter
                            for cell in column[:max_rows_for_width]:
                                try:
                                    cell_length = len(str(cell.value))
                                    if cell_length > max_length:
                                        max_length = cell_length
                                except:
                                    pass
                            adjusted_width = min(max_length + 2, 50)
                            worksheet.column_dimensions[column_letter].width = adjusted_width

        print(f"✅ Файл сохранен: {filename}")

        # Выводим статистику
        print("\n📊 СТАТИСТИКА:")
        print("-" * 40)
        total = 0
        for sheet_name, df in self.dataframes.items():
            count = len(df)
            total += count
            print(f"  {sheet_name:25} - {count} записей")
        print(f"\n  📈 ВСЕГО ЗАПИСЕЙ: {total}")

    def render_address_config_lines(self, names: Optional[List[str]] = None) -> List[str]:
        target_names = names if names is not None else sorted(self.address_objects.keys(), key=str.lower)
        lines: List[str] = ["config firewall address"]
        for name in target_names:
            lines.extend(self._build_address_command_block(name))
        lines.append("end")
        return lines

    def render_addrgrp_config_lines(self, names: Optional[List[str]] = None) -> List[str]:
        target_names = names if names is not None else sorted(self.address_group_objects.keys(), key=str.lower)
        lines: List[str] = ["config firewall addrgrp"]
        for name in target_names:
            lines.extend(self._build_addrgrp_command_block(name))
        lines.append("end")
        return lines


def main():
    """Главная функция"""
    print("=" * 70)
    print("FORTIGATE КОНФИГУРАЦИОННЫЙ АНАЛИЗАТОР")
    print("=" * 70)
    print("Создает Excel файл с полным анализом конфигурации FortiGate")
    print()

    # Проверяем наличие файла конфигурации
    config_file = "fortigate.conf"
    if not os.path.exists(config_file):
        config_file = input("Введите путь к файлу конфигурации FortiGate: ").strip()
        if not os.path.exists(config_file):
            print(f"❌ Файл не найден: {config_file}")
            print("\nСоздайте файл конфигурации командой на FortiGate:")
            print("  show full-configuration")
            print("Сохраните вывод в файл fortigate.conf в этой папке.")
            sys.exit(1)

    # Создаем парсер
    parser = FortigateConfigParser(config_file)

    # Парсим все
    parser.parse_all()

    # Сохраняем в Excel
    output_file = "fortigate_анализ.xlsx"
    parser.save_to_excel(output_file)

    print("\n" + "=" * 70)
    print("🎉 АНАЛИЗ ЗАВЕРШЕН УСПЕШНО!")
    print("=" * 70)
    print(f"\n📁 Файл с результатами: {output_file}")
    print("\n📋 Содержимое:")
    print("  • Локальные_пользователи - Учетные записи на FortiGate")
    print("  • Группы_пользователей - Группы пользователей")
    print("  • Firewall_правила - Все правила фаервола (ВСЕ поля)")
    print("  • IPSec_Туннели - Туннели site-to-site")
    print("  • Статические_маршруты - Таблица маршрутизации")
    print("  • NAT_правила - Правила преобразования адресов")
    print("  • Адреса - Объекты firewall address")
    print("  • Группы_адресов - Объекты firewall addrgrp")
    print("  • VPN_Пользователи - Доступ по VPN")
    print("\nОткройте файл в Excel или LibreOffice Calc.")


if __name__ == "__main__":
    # Проверяем зависимости
    try:
        import pandas as pd
        import openpyxl
    except ImportError as e:
        print("❌ Отсутствуют необходимые библиотеки!")
        print("Установите их командой:")
        print("  pip install pandas openpyxl")
        sys.exit(1)

    main()