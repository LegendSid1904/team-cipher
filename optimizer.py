import numpy as np


def evaluate_subset(X, y, subset):
    selected = X[:, subset]

    if selected.shape[1] == 0:
        return 0.0

    weights = np.mean(selected, axis=0)

    if np.all(weights == 0):
        return 0.0

    score = 0.0

    for i in range(len(y)):
        value = np.mean(selected[i])

        prediction = 1 if value > 0.5 else 0

        if prediction == y[i]:
            score += 1

    return score / len(y)


def quantum_inspired_feature_selection(
    X,
    y,
    iterations=20,
    samples_per_iteration=30
):
    n_features = X.shape[1]

    # Probability of choosing each feature
    probabilities = np.full(n_features, 0.5)

    best_subset = list(range(n_features))
    best_score = 0.0

    for _ in range(iterations):
        iteration_best_subset = None
        iteration_best_score = -1

        for _ in range(samples_per_iteration):

            random_values = np.random.random(n_features)

            subset = [
                i for i in range(n_features)
                if random_values[i] < probabilities[i]
            ]

            if not subset:
                subset = [np.random.randint(0, n_features)]

            score = evaluate_subset(X, y, subset)

            if score > iteration_best_score:
                iteration_best_score = score
                iteration_best_subset = subset

            if score > best_score:
                best_score = score
                best_subset = subset

        # Move probabilities toward the best candidate
        for feature_index in range(n_features):
            if feature_index in iteration_best_subset:
                probabilities[feature_index] = min(
                    0.95,
                    probabilities[feature_index] + 0.05
                )
            else:
                probabilities[feature_index] = max(
                    0.05,
                    probabilities[feature_index] - 0.02
                )

    return best_subset, best_score


if __name__ == "__main__":
    from train_model import create_dataset, FEATURES

    df = create_dataset()

    X = df[FEATURES].values
    y = df["label"].values

    selected, score = quantum_inspired_feature_selection(X, y)

    print("Selected feature indexes:", selected)
    print("Optimization score:", score)

    print("Selected features:")

    for index in selected:
        print(FEATURES[index])
