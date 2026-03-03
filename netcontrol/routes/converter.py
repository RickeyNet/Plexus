from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
import os
import sys
import tempfile
import subprocess
import shutil

# Adjust import path for converter scripts
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../Firewall_converter/FortiGateToFTDTool')))

router = APIRouter()

@router.post('/api/convert-fortigate')
async def convert_fortigate(
    yaml_file: UploadFile = File(...),
    ftd_host: str = Form(...),
    ftd_username: str = Form(...),
    ftd_password: str = Form(...),
    deploy: bool = Form(False)
):
    """
    Accepts a FortiGate YAML config, converts it to FTD JSON, and imports it using the Cisco API.
    """
    # Save uploaded YAML to temp file
    with tempfile.TemporaryDirectory() as tmpdir:
        # Ensure filename is not None and safe
        filename = yaml_file.filename or 'input.yaml'
        yaml_path = os.path.join(tmpdir, filename)
        with open(yaml_path, 'wb') as f:
            f.write(await yaml_file.read())

        # Run the converter script
        converter_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../Firewall_converter/FortiGateToFTDTool/fortigate_converter.py'))
        proc = subprocess.run([
            sys.executable, converter_path, yaml_path
        ], cwd=tmpdir, capture_output=True, text=True)
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Conversion failed: {proc.stderr}")

        # Find the base name for output files
        base = os.path.splitext(os.path.basename(filename))[0]
        # Run the importer script
        importer_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../Firewall_converter/FortiGateToFTDTool/ftd_api_importer.py'))
        import_args = [
            sys.executable, importer_path,
            '--host', ftd_host,
            '--username', ftd_username,
            '--password', ftd_password,
            '--base', base
        ]
        if deploy:
            import_args.append('--deploy')
        proc2 = subprocess.run(import_args, cwd=tmpdir, capture_output=True, text=True)
        if proc2.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Import failed: {proc2.stderr}")

        return JSONResponse({
            'ok': True,
            'conversion_output': proc.stdout,
            'import_output': proc2.stdout
        })
