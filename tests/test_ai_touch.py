from pst_gate.ai_touch import ai_touched_paths, finding_ai_touched


def test_copilot_trailer_marks_diff_files():
    diff = """
diff --git a/app/main.py b/app/main.py
index 111..222 100644
--- a/app/main.py
+++ b/app/main.py
@@ -1,0 +1,2 @@
+# Co-authored-by: Copilot <copilot@github.com>
+x = 1
"""
    paths = ai_touched_paths(diff)
    assert "app/main.py" in paths
    assert finding_ai_touched("app/main.py", paths)
    assert not finding_ai_touched("infra/s3.tf", paths)
