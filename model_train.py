import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

(X_train, X_val, X_test, y_train, y_val, y_test, scaler, features) = joblib.load('preprocessed_data.pkl')

lr = LogisticRegression(max_iter=1000)
rf = RandomForestClassifier(n_estimators=200, random_state=42)
gb = GradientBoostingClassifier()

ensemble = VotingClassifier(estimators=[('lr', lr), ('rf', rf), ('gb', gb)], voting='soft')
ensemble.fit(X_train, y_train)

print("Val acc:", accuracy_score(y_val, ensemble.predict(X_val)))
print("Test acc:", accuracy_score(y_test, ensemble.predict(X_test)))

cm = confusion_matrix(y_test, ensemble.predict(X_test))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.xlabel('Predicted'); plt.ylabel('Actual'); plt.title('Confusion Matrix')
plt.show()

joblib.dump(ensemble, 'ensemble_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
print("Model saved.")