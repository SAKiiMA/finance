# finance

### web app for online trading stock shares_CS50

This web-app has been developed for course **CS50_fall 2018** reference to **[Problem set 8](https://docs.cs50.net/2019/x/psets/8/finance/finance.html)**

#### How to Run the App:  
`pip install -r requirements.txt`  

_get database raedy_    
`$ sudo apt install sqlite3 #if not installed already`  
`$ sqlite3 finance.db`  
_Follow "database_model.txt" to craete tables_  
`$ export FLASK_APP=application.py`  
`$ export API_KEY=your_key`  
`flask run`

Running the app will require an API_KEY to talk to **[IEX Cloud](https://iexcloud.io/)**. You may register and obtain your own KEY. Then export it as an environmental variable before running the `flask`.

`$ export API_KEY=<xxxx>`

_P.S.: SQLite database_
