using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Models;

namespace IcsThreatClassification.Domain.Abstractions;

/// <summary>
/// Интерфейс для генерации синтетического набора данных.
/// </summary>
public interface ISyntheticDatasetGenerator
{
    /// <summary>
    /// Генерирует синтетический набор данных с размеченными образцами для каждого типа угрозы.
    /// </summary>
    IReadOnlyCollection<LabeledSensorSample> Generate(SyntheticDatasetOptions options);
}
