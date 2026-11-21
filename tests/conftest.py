import pytest_asyncio

from .helpers import start_relay


@pytest_asyncio.fixture
async def relay_factory(tmp_path):
    relays = []

    async def make(issuer=None, managed_tls=False, **overrides):
        r = await start_relay(tmp_path / f"r{len(relays)}", issuer, managed_tls, **overrides)
        relays.append(r)
        return r

    yield make
    for r in relays:
        await r.stop()
        r.store.close()
