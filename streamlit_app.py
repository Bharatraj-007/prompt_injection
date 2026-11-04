"""
Streamlit Community Cloud default entry point alias.
Executes the main application defined in app.py.
"""
import runpy

if __name__ == "__main__":
    runpy.run_module("app", run_name="__main__")
else:
    import app
