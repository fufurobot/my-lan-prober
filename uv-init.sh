# core

uv add pandas tqdm

# extra

uv add --optional ssh asyncssh
uv add --optional vnc asyncvnc
uv add --optional openai openai
uv add --optional dns dnspython
uv add --optional mdns zeroconf
uv add --optional playwright playwright
uv add --optional arrow pyarrow
uv add --optional wifi pywifi
uv add --optional bluetooth bleak

# Special dev group (synced by default)
uv add --dev ty ruff mypy pytest pytest-asyncio types-requests
