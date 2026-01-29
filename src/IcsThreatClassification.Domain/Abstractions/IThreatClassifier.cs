using IcsThreatClassification.Domain.Entities;

namespace IcsThreatClassification.Domain.Abstractions;

/// <summary>
/// Базовый интерфейс для движков классификации угроз.
/// </summary>
public interface IThreatClassifier
{
    /// <summary>
    /// Классифицирует данное чтение сенсора и возвращает обнаруженный тип угрозы с уверенностью.
    /// </summary>
    ThreatClassificationResult Classify(SensorReading reading);
}

/// <summary>
/// Маркерный интерфейс для классического классификатора угроз на основе правил.
/// </summary>
public interface IClassicThreatClassifier : IThreatClassifier
{
}

/// <summary>
/// Маркерный интерфейс для классификатора угроз на основе машинного обучения.
/// </summary>
public interface IMlThreatClassifier : IThreatClassifier
{
    /// <summary>
    /// Указывает, загружена ли ML-модель и готова ли к инференсу.
    /// </summary>
    bool IsModelLoaded { get; }
}
