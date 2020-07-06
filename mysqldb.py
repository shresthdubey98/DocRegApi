import mysql.connector
import yaml
db = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
mydb = mysql.connector.connect(
    host=db['mysql_host'],
    user=db['mysql_user'],
    passwd=db['mysql_password'],
    database=db['mysql_db']
)