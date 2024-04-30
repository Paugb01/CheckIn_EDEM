import base64
import json
from google.cloud import bigquery

# Inicializa el cliente de BigQuery
client = bigquery.Client()

def verify_and_update_data(event, context):
    # Decodifica el mensaje de Pub/Sub
    if 'data' in event:
        message_data = base64.b64decode(event['data']).decode('utf-8')
        data = json.loads(message_data)
        mac_address = data['mac']

        # Verifica y escribe en BigQuery
        if not check_if_exists(mac_address):
            write_to_bigquery(data)

        # Sincroniza los registros de BigQuery
        synchronize_bigquery([mac_address])

def check_if_exists(mac_address):
    query = f"""
    SELECT mac
    FROM `your_project.your_dataset.your_table`
    WHERE mac = '{mac_address}'
    """
    query_job = client.query(query)
    results = list(query_job)
    return len(results) > 0

def write_to_bigquery(data):
    table_id = "your_project.your_dataset.your_table"
    rows_to_insert = [data]
    errors = client.insert_rows_json(table_id, rows_to_insert)
    if errors == []:
        print("New rows have been added.")
    else:
        print("Encountered errors while inserting rows: {}".format(errors))

def synchronize_bigquery(current_macs):
    # Obtén todos los MACs de BigQuery
    query = """
    SELECT mac
    FROM `your_project.your_dataset.your_table`
    """
    macs_in_bigquery = [row['mac'] for row in client.query(query)]
    
    # Determina los MACs a eliminar
    macs_to_drop = [mac for mac in macs_in_bigquery if mac not in current_macs]
    
    # Elimina los MACs no deseados
    for mac in macs_to_drop:
        query = f"DELETE FROM `your_project.your_dataset.your_table` WHERE mac = '{mac}'"
        client.query(query)

# Nota: asegúrate de configurar el trigger de Pub/Sub correctamente al desplegar la función
