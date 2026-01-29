namespace IcsThreatClassification.Domain.Configuration;

/// <summary>
/// Параметры конфигурации для генерации синтетического набора данных.
/// </summary>
public sealed class SyntheticDatasetOptions
{
    /// <summary>
    /// Количество образцов для генерации на каждый тип угрозы.
    /// </summary>
    public int SamplesPerThreatType { get; init; } = 500;

    /// <summary>
    /// Случайное начальное значение для воспроизводимости.
    /// </summary>
    public int? Seed { get; init; }

    /// <summary>
    /// Множитель стандартного отклонения для вариации признаков.
    /// </summary>
    public double NoiseLevel { get; init; } = 0.15;

    public static SyntheticDatasetOptions Default => new();
}
