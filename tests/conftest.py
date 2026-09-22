from hypothesis import settings

# Shared CI runners have noisy timing, so a per-example deadline only adds flaky failures.
settings.register_profile("pilotfish", deadline=None)
settings.load_profile("pilotfish")
