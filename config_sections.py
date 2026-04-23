def replace_or_append_config_section(config_text: str, section_name: str, section_body: str) -> str:
    target = f"config {section_name}".lower()
    lines = config_text.splitlines()
    start_idx = -1
    end_idx = -1
    depth = 0
    in_target = False

    for idx, raw in enumerate(lines):
        line = raw.strip().lower()
        if not in_target:
            if line == target:
                in_target = True
                start_idx = idx
                depth = 1
            continue
        if line.startswith("config "):
            depth += 1
            continue
        if line == "end":
            depth -= 1
            if depth == 0:
                end_idx = idx
                break

    section_lines = section_body.splitlines()
    if start_idx >= 0 and end_idx >= start_idx:
        rebuilt = lines[:start_idx] + section_lines + lines[end_idx + 1 :]
    else:
        rebuilt = lines[:]
        if rebuilt and rebuilt[-1].strip():
            rebuilt.append("")
        rebuilt.extend(section_lines)
    return "\n".join(rebuilt).rstrip() + "\n"
