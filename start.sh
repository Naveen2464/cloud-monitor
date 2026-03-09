# Still inside cloud folder run this:
@"
#!/bin/bash
echo "Starting Cloud Monitor..."
touch app.log alerts.log
cd elk
docker-compose up -d
cd ..
echo "Waiting 60 seconds for ELK..."
sleep 60
cd elk
python setup_kibana.py
cd ..
python app.py
"@ | Out-File -FilePath "start.sh" -Encoding UTF8


