from groq import Groq

# Create a client instance with your Groq API key
client = Groq(api_key="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")

try:
    response = client.chat.completions.create(
        model="llama3-8b-8192",  # Groq's available model
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"},
        ]
    )
    print("Groq API key is working! Here's a test response:")
    print(response.choices[0].message.content)

except Exception as e:
    print(f"An error occurred: {e}")