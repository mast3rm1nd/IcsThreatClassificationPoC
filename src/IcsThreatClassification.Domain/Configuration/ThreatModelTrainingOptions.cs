namespace IcsThreatClassification.Domain.Configuration;

/// <summary>
/// Параметры конфигурации для обучения ML-модели.
/// </summary>
public sealed class ThreatModelTrainingOptions
{
    /// <summary>
    /// Количество итераций обучения.
    /// </summary>
    public int NumberOfIterations { get; init; } = 100;

    /// <summary>
    /// Скорость обучения для оптимизатора.
    /// </summary>
    public double LearningRate { get; init; } = 0.1;

    /// <summary>
    /// Включить ускорение GPU, если доступно.
    /// </summary>
    public bool UseGpu { get; init; }

    /// <summary>
    /// Доля данных для использования в валидации.
    /// </summary>
    public double ValidationFraction { get; init; } = 0.2;

    /// <summary>
    /// Случайное начальное значение для воспроизводимости.
    /// </summary>
    public int? Seed { get; init; }

    public static ThreatModelTrainingOptions Default => new();
}
