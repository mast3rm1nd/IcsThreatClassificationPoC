using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.Domain.ValueObjects;

namespace IcsThreatClassification.ClassicEngine.Rules;

/// <summary>
/// Представляет единое правило обнаружения угроз с логикой оценки.
/// </summary>
internal sealed class ThreatRule
{
    public IcsThreatType ThreatType { get; }
    public Func<SensorFeatureVector, double> ScoreFunction { get; }
    public Func<SensorFeatureVector, string[]> GetTriggeredIndicators { get; }

    public ThreatRule(
        IcsThreatType threatType,
        Func<SensorFeatureVector, double> scoreFunction,
        Func<SensorFeatureVector, string[]> getTriggeredIndicators)
    {
        ThreatType = threatType;
        ScoreFunction = scoreFunction ?? throw new ArgumentNullException(nameof(scoreFunction));
        GetTriggeredIndicators = getTriggeredIndicators ?? throw new ArgumentNullException(nameof(getTriggeredIndicators));
    }
}
