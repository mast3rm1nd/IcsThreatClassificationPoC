using IcsThreatClassification.ClassicEngine.Rules;
using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.Domain.Entities;
using IcsThreatClassification.Domain.Enums;

namespace IcsThreatClassification.ClassicEngine;

/// <summary>
/// Классификатор угроз на основе правил с предопределёнными правилами обнаружения и оценкой.
/// </summary>
public sealed class ClassicThreatClassifier : IClassicThreatClassifier
{
    private readonly IReadOnlyList<ThreatRule> _rules;
    private const double DetectionThreshold = 0.5;

    public ClassicThreatClassifier()
    {
        _rules = ThreatRuleSet.CreateRules();
    }

    public ThreatClassificationResult Classify(SensorReading reading)
    {
        ArgumentNullException.ThrowIfNull(reading);

        var features = reading.Features;
        var scores = new List<(IcsThreatType Type, double Score, string[] Indicators)>();

        foreach (var rule in _rules)
        {
            double score = rule.ScoreFunction(features);
            if (score >= DetectionThreshold)
            {
                var indicators = rule.GetTriggeredIndicators(features);
                scores.Add((rule.ThreatType, score, indicators));
            }
        }

        if (scores.Count == 0)
        {
            return ThreatClassificationResult.NoThreat(
                "Угрозы не обнаружены. Все индикаторы в пределах нормальных рабочих значений.");
        }

        var (topThreat, confidence, topIndicators) = scores.OrderByDescending(s => s.Score).First();

        string explanation = BuildExplanation(topThreat, topIndicators);

        return new ThreatClassificationResult(topThreat, confidence, explanation);
    }

    private static string BuildExplanation(IcsThreatType threatType, string[] indicators)
    {
        string threatDescription = GetThreatDescription(threatType);
        string indicatorList = indicators.Length > 0
            ? string.Join("; ", indicators)
            : "Несколько слабых индикаторов в совокупности";

        return $"{threatDescription} Индикаторы: {indicatorList}.";
    }

    private static string GetThreatDescription(IcsThreatType threatType)
    {
        return threatType switch
        {
            IcsThreatType.UnauthorizedRemoteAccess =>
                "Обнаружена попытка несанкционированного удалённого доступа.",
            IcsThreatType.MaliciousCommandInjection =>
                "Потенциальное внедрение вредоносных команд в полевые устройства.",
            IcsThreatType.ConfigurationTampering =>
                "Обнаружена активность по изменению конфигурации компонентов АСУ ТП.",
            IcsThreatType.DenialOfService =>
                "Выявлен паттерн атаки типа отказ в обслуживании.",
            IcsThreatType.RansomwareActivity =>
                "Обнаружено поведение, характерное для программы-вымогателя в OT-сегменте.",
            IcsThreatType.DataExfiltration =>
                "Обнаружена попытка эксфильтрации данных.",
            IcsThreatType.ManInTheMiddle =>
                "Присутствуют индикаторы атаки типа человек посередине.",
            IcsThreatType.ProtocolMisuse =>
                "Обнаружено неправильное использование или искажение промышленного протокола.",
            IcsThreatType.BruteForceAuthentication =>
                "Атака подбора паролей в процессе.",
            IcsThreatType.SuspiciousEngineeringWorkstationActivity =>
                "Подозрительная активность с инженерной рабочей станции.",
            _ => "Обнаружен неизвестный паттерн угрозы."
        };
    }
}
