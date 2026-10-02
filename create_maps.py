import yaml

with open('bluekit/logs/fieldmap.yaml', 'r') as f:
    data = yaml.safe_load(f)

default = {}
for preset, fields in data['presets'].items():
    for canon, cols in fields.items():
        if canon not in default:
            default[canon] = set()
        default[canon].update(cols)
        
for k in default:
    default[k] = list(default[k])
    
data['default'] = default
with open('bluekit/logs/fieldmap.yaml', 'w') as f:
    yaml.dump(data, f, sort_keys=False)
