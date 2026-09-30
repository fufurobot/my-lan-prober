# core

uv add pandas tqdm --python 3.10

# extra

uv add --optional ssh asyncssh --python 3.10
uv add --optional vnc asyncvnc --python 3.10
uv add --optional openai openai --python 3.10
uv add --optional dns dnspython --python 3.10
uv add --optional mdns zeroconf --python 3.10
uv add --optional playwright playwright --python 3.10
uv add --optional arrow pyarrow --python 3.10
uv add --optional wifi pywifi --python 3.10
uv add --optional bluetooth bleak --python 3.10

# Special dev group (synced by default)
uv add --dev ty ruff mypy pytest pytest-asyncio types-requests --python 3.10
