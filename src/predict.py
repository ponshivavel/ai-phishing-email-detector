import pickle

# Load model
model = pickle.load(open("model/phishing_model.pkl", "rb"))
vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))

email = ["Your account is suspended. Click here to verify immediately"]

X = vectorizer.transform(email)

prediction = model.predict(X)

if prediction[0] == 1:
    print("⚠️ Phishing Email Detected")
else:
    print("✅ Safe Email")

