content = open('main.py', 'r', encoding='utf-8').read()

content = content.replace(
    'from modules.api_endpoints import check_api_endpoints',
    'from modules.api_endpoints import check_api_endpoints\nfrom modules.ct_logs import check_ct_logs'
)

content = content.replace(
    '    exposed_paths = check_exposed_paths(domain)',
    '    ct_subdomains = check_ct_logs(domain)\n    exposed_paths = check_exposed_paths(domain)'
)

content = content.replace(
    '        "exposed_paths": exposed_paths,',
    '        "ct_subdomains": ct_subdomains,\n        "exposed_paths": exposed_paths,'
)

open('main.py', 'w', encoding='utf-8').write(content)
print('OK')
