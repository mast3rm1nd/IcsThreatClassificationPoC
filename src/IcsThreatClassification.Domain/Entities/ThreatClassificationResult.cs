using IcsThreatClassification.Domain.Enums;

namespace IcsThreatClassification.Domain.Entities;

/// <summary>
/// Результат классификации угрозы, включающий предсказанный тип угрозы,
/// уровень уверенности и человекочитаемое объяснение.
/// </summary>
public sealed record ThreatClassificationResult
{
    public IcsThreatType ThreatType { get; }
    public double Confidence { get; }
    public string Explanation { get; }

    public ThreatClassificationResult(IcsThreatType threatType, double confidence, string explanation)
    {
        if (confidence < 0.0 || confidence > 1.0)
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), "Уверенность должна быть между 0.0 и 1.0.");
        }

        ThreatType = threatType;
        Confidence = confidence;
        Explanation = explanation ?? string.Empty;
    }

    public bool IsThreatDetected => ThreatType != IcsThreatType.None;

    public static ThreatClassificationResult NoThreat(string explanation = "Индикаторы угроз не обнаружены.")
    {
        return new ThreatClassificationResult(IcsThreatType.None, 1.0, explanation);
    }
}
