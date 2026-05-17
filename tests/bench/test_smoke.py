def test_bench_importable():
    import bench
    assert hasattr(bench, "__version__")

def test_bench_runnable_as_module():
    import subprocess
    import sys
    result = subprocess.run(
        [sys.executable, "-m", "bench", "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "bench" in result.stdout.lower()
