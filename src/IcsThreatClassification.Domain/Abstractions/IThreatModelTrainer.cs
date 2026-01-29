using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Models;

namespace IcsThreatClassification.Domain.Abstractions;

/// <summary>
/// Интерфейс для операций обучения ML-модели.
/// </summary>
public interface IThreatModelTrainer
{
    /// <summary>
    /// Обучает модель классификации, используя предоставленный размеченный набор данных.
    /// </summary>
    void Train(IEnumerable<LabeledSensorSample> dataset, ThreatModelTrainingOptions options);

    /// <summary>
    /// Сохраняет обученную модель по указанному пути.
    /// </summary>
    void Save(string path);

    /// <summary>
    /// Загружает ранее обученную модель по указанному пути.
    /// </summary>
    void Load(string path);

    /// <summary>
    /// Указывает, загружена ли в данный момент модель.
    /// </summary>
    bool IsModelLoaded { get; }
}
