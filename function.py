import os
from google.cloud import bigquery
import pymysql
import json
from datetime import datetime

# Configura el cliente de BigQuery
client = bigquery.Client()

def decode_json(message):
    # Decodificar mensaje de Pub/Sub
    pubsub_message = message.decode('utf-8')
    
    # Convertir string decodificado en formato JSON
    msg = json.loads(pubsub_message)
    
    # Retorna el mensaje JSON
    return msg

def verify_and_log(event, context):
    # Obtener y decodificar el mensaje de Pub/Sub
    message = event['data']  # Accede al dato del evento de Pub/Sub
    request_json = decode_json(message)

    if 'mac' in request_json:
        mac_address = request_json['mac']
        
        # Conectar a Cloud SQL para verificar el MAC
        connection = pymysql.connect(host=os.environ['INSTANCE_CONNECTION_NAME'],
                                     user=os.environ['DB_USER'],
                                     password=os.environ['DB_PASS'],
                                     db=os.environ['DB_NAME'])
        try:
            with connection.cursor() as cursor:
                # Verificar si el MAC está registrado
                sql = "SELECT COUNT(*) FROM registered_devices WHERE mac = %s"
                cursor.execute(sql, (mac_address,))
                result = cursor.fetchone()
                
                if result[0] > 0:
                    # MAC está registrado, verifica en BigQuery en la tabla 'mac_list'
                    query = f"""
                        SELECT mac FROM `{os.environ['BQ_DATASET']}.mac_list`
                        WHERE mac = '{mac_address}'
                    """
                    query_job = client.query(query)
                    results = list(query_job)

                    if len(results) == 0:
                        # No hay entradas con esa MAC, escribimos los datos
                        table_id = f"{os.environ['BQ_DATASET']}.mac_list"
                        rows_to_insert = [
                            {u"mac": request_json['mac'], u"ip": request_json['ip'], u"timestamp": request_json['timestamp']}
                        ]
                        client.insert_rows(table_id, rows_to_insert)
                        print("New MAC entry added to mac_list.")
                    else:
                        # MAC está en BigQuery, reescribe el registro en 'disconnects'
                        disconnect_table_id = f"{os.environ['BQ_DATASET']}.disconnects"
                        current_timestamp = datetime.utcnow().isoformat()
                        disconnect_rows_to_insert = [
                            {u"mac": mac_address, u"timestamp": current_timestamp}
                        ]
                        client.insert_rows_json(disconnect_table_id, disconnect_rows_to_insert)
                        print("Disconnect entry added.")

                        # Eliminar la MAC de 'mac_list'
                        delete_query = f"""
                            DELETE FROM `{os.environ['BQ_DATASET']}.mac_list` WHERE mac = '{mac_address}'
                        """
                        client.query(delete_query)
                        print("MAC removed from mac_list.")
                else:
                    # MAC no está registrado, registra en BigQuery en 'unknown_users'
                    unknown_table_id = f"{os.environ['BQ_DATASET']}.unknown_users"
                    unknown_rows_to_insert = [
                        {u"mac": request_json['mac'], u"ip": request_json['ip'], u"timestamp": request_json['timestamp']}
                    ]
                    client.insert_rows_json(unknown_table_id, unknown_rows_to_insert)
                    print("MAC entry added to unknown_users.")

        finally:
            connection.close()

    return 'Function executed successfully!'

