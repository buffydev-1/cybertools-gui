import asyncio

async def _check_port(host, port, timeout=1.0):
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def scan_ports(host, ports, concurrency=200, timeout=1.0):
    sem = asyncio.Semaphore(concurrency)
    open_ports = []

    async def worker(p):
        async with sem:
            ok = await _check_port(host, p, timeout=timeout)
            if ok:
                open_ports.append(p)

    tasks = [worker(p) for p in ports]
    await asyncio.gather(*tasks)
    open_ports.sort()
    return open_ports
