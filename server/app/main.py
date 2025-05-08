# Importing the create_app function from the ./NetFlowInsight package
from NetFlowInsight import create_app

# Creating the app
app = create_app()

# Will run only if this script is directly executed
if __name__ == '__main__':
    # Running on port 80
    app.run(debug=True, port=80, host='0.0.0.0')
