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
import re
from collections import defaultdict
from typing import Dict, List, Optional, Set
import sys
import os


class FortigateConfigParser:
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config_data = self._read_config()
        self.dataframes = {}
        self.address_objects: Dict[str, Dict[str, str]] = {}
        self.address_group_objects: Dict[str, Dict[str, str]] = {}
        self.address_group_members: Dict[str, List[str]] = {}

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

    def _extract_blocks(self, block_name: str) -> List[Dict]:
        """Извлекает все edit/next блоки из нужного config-раздела."""
        target = f"config {block_name}".lower()
        lines = self.config_data.splitlines()
        all_blocks: List[Dict] = []

        in_target = False
        config_depth = 0
        current_block: Dict | None = None

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            lower = line.lower()

            if not in_target:
                if lower == target:
                    in_target = True
                    config_depth = 1
                continue

            # Track nested config/end to stay inside the exact target section.
            if lower.startswith("config "):
                config_depth += 1
                continue

            if lower == "end":
                config_depth -= 1
                if config_depth == 0:
                    if current_block is not None:
                        all_blocks.append(current_block)
                        current_block = None
                    in_target = False
                continue

            # Parse edit/next/set only on top level of this config section.
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
                value = parts[2].strip() if len(parts) > 2 else ""

                quoted_values = re.findall(r'"([^"]*)"', value)
                if quoted_values:
                    value = " ".join(quoted_values)
                elif value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]

                current_block[param] = value

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

    def _build_address_command_block(self, name: str) -> List[str]:
        obj = self.address_objects.get(name, {})
        lines = [f'    edit {self._quote(name)}']
        for key, value in obj.items():
            if key in {"_name", "uuid"}:
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

    def build_transfer_plan(
        self,
        selected_addresses: Set[str],
        selected_groups: Set[str],
        existing_names: Set[str],
        group_color_overrides: Optional[Dict[str, int]] = None,
    ) -> Dict[str, object]:
        """Build transfer command plan while skipping duplicates on target."""
        group_color_overrides = group_color_overrides or {}
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
                command_lines.extend(self._build_address_command_block(name))
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

        # Собираем ВСЕ уникальные поля из всех правил
        all_fields = set()
        for rule in rules:
            all_fields.update(rule.keys())

        # Преобразуем в список и сортируем
        all_fields = sorted(all_fields)

        data = []
        for idx, rule in enumerate(rules, 1):
            row = {'№': idx}

            # Проходим по всем возможным полям
            for field in all_fields:
                # Переводим имя поля
                russian_field = self.firewall_translations.get(field, field)

                # Получаем значение
                value = rule.get(field, '')

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
        vpn_groups = self._extract_blocks('user group')
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

        self.parse_local_users()
        self.parse_user_groups()
        self.parse_firewall_rules()
        self.parse_ipsec_tunnels()
        self.parse_static_routes()
        self.parse_nat_rules()
        self.parse_addresses()
        self.parse_vpn_users()

        print("\n✅ ПАРСИНГ ЗАВЕРШЕН!")

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
                        # Сохраняем в Excel
                        df.to_excel(writer, sheet_name=sheet_name, index=False)

                        # Настраиваем ширину столбцов
                        worksheet = writer.sheets[sheet_name]
                        for column in worksheet.columns:
                            max_length = 0
                            column_letter = column[0].column_letter
                            for cell in column:
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