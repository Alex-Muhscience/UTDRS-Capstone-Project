"""Settings as hosting platforms give them."""
from config import Settings


def test_an_engine_address_without_a_scheme_gets_one():
    assert Settings(MONGODB_URI="mongodb://x", JWT_SECRET="x", CORE_ENGINE_URL="utdrs-core-engine:8000").CORE_ENGINE_URL == "http://utdrs-core-engine:8000"
    assert Settings(MONGODB_URI="mongodb://x", JWT_SECRET="x", CORE_ENGINE_URL="https://e.example").CORE_ENGINE_URL == "https://e.example"
    assert Settings(MONGODB_URI="mongodb://x", JWT_SECRET="x").CORE_ENGINE_URL is None


def test_preview_origins_by_pattern():
    import re

    pattern = re.compile(r"^https://utdrs-capstone-project-[a-z0-9-]+\.vercel\.app$")  # as render.yaml sets it
    assert pattern.match("https://utdrs-capstone-project-3dol09oqu.vercel.app")
    assert pattern.match("https://utdrs-capstone-project-git-main-team.vercel.app")
    assert not pattern.match("https://utdrs-capstone-project.vercel.app.evil.example")
    assert not pattern.match("http://utdrs-capstone-project-3dol09oqu.vercel.app")
