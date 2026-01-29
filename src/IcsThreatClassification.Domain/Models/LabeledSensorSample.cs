using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.Domain.ValueObjects;

namespace IcsThreatClassification.Domain.Models;

/// <summary>
/// Размеченный образец для обучения ML, содержащий вектор признаков и метку типа угрозы.
/// </summary>
public sealed record LabeledSensorSample
{
    public SensorFeatureVector Features { get; }
    public IcsThreatType Label { get; }

    public LabeledSensorSample(SensorFeatureVector features, IcsThreatType label)
    {
        Features = features ?? throw new ArgumentNullException(nameof(features));
        Label = label;
    }
}
