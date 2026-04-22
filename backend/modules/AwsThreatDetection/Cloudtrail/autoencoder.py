# import pandas as pd
# import numpy as np
# import json
# import requests
# import os
# from botocore.exceptions import ClientError

# from utils.exceptions import handle_error

# from datetime import datetime
# import numpy as np
# import keras
# from sklearn.model_selection import train_test_split
# import json
# import pandas as pd
# from sklearn.preprocessing import StandardScaler, LabelEncoder


# from ML.Cloudtrail.getCTDF import getCTLogsDF


def getAutoEncoderPrediction(df, X_scaled):
    return {"status": "error", "error_message": "str(e)"}

    # try:

    #     model = keras.Sequential(
    #         [
    #             keras.layers.Dense(
    #                 128, activation="relu", input_shape=(X_scaled.shape[1],)
    #             ),
    #             keras.layers.Dense(64, activation="relu"),
    #             keras.layers.Dense(32, activation="relu"),
    #             keras.layers.Dense(64, activation="relu"),
    #             keras.layers.Dense(128, activation="relu"),
    #             keras.layers.Dense(X_scaled.shape[1], activation="linear"),
    #         ]
    #     )

    #     model.compile(optimizer="adam", loss="mse")

    #     X_train, X_test = train_test_split(X_scaled, test_size=0.2, random_state=42)

    #     early_stop = keras.callbacks.EarlyStopping(
    #         monitor="val_loss", patience=2, restore_best_weights=True
    #     )

    #     # Train
    #     history = model.fit(
    #         X_train,
    #         X_train,
    #         epochs=50,
    #         batch_size=64,
    #         validation_data=(X_test, X_test),
    #         callbacks=[early_stop],
    #     )

    #     # reconstruction loss
    #     def calculate_reconstruction_loss(data, model):
    #         reconstructions = model.predict(data)
    #         reconstruction_errors = np.mean(
    #             np.power((data - reconstructions), 2), axis=1
    #         )
    #         return reconstruction_errors

    #     # Evaluate model
    #     reconstruction_loss_normal = calculate_reconstruction_loss(X_scaled, model)

    #     threshold = np.percentile(reconstruction_loss_normal, 95)

    #     df["is_anomaly_auto_encoder"] = reconstruction_loss_normal > threshold

    #     return df
    # except Exception as e:
    #     print(f"Error: {str(e)}")
    #     return {"status": "error", "error_message": str(e)}
