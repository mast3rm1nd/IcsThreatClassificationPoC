using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.Domain.Entities;
using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.MlEngine.Training;
using Microsoft.ML;

namespace IcsThreatClassification.MlEngine.Inference;

/// <summary>
/// ML-классификатор угроз с использованием обученной модели для инференса.
/// </summary>
public sealed class MlThreatClassifier : IMlThreatClassifier
{
    private readonly ThreatClassificationTrainer _trainer;
    private PredictionEngine<MlTrainingData, MlPredictionData>? _predictionEngine;

    public bool IsModelLoaded => _trainer.IsModelLoaded;

    public MlThreatClassifier(ThreatClassificationTrainer trainer)
    {
        _trainer = trainer ?? throw new ArgumentNullException(nameof(trainer));
    }

    public ThreatClassificationResult Classify(SensorReading reading)
    {
        ArgumentNullException.ThrowIfNull(reading);

        if (!IsModelLoaded)
        {
            throw new InvalidOperationException("ML-модель не загружена. Сначала обучите или загрузите модель.");
        }

        EnsurePredictionEngine();

        var input = ConvertToMlData(reading);
        var prediction = _predictionEngine!.Predict(input);

        var predictedType = (IcsThreatType)prediction.PredictedLabel;
        double confidence = CalculateConfidence(prediction.Score);

        string explanation = BuildExplanation(predictedType, confidence);

        return new ThreatClassificationResult(predictedType, confidence, explanation);
    }

    private void EnsurePredictionEngine()
    {
        if (_predictionEngine != null)
        {
            return;
        }

        var model = _trainer.GetTrainedModel();
        if (model == null)
        {
            throw new InvalidOperationException("Обученная модель недоступна.");
        }

        _predictionEngine = _trainer.GetMlContext()
            .Model.CreatePredictionEngine<MlTrainingData, MlPredictionData>(model);
    }

    private static double CalculateConfidence(float[] scores)
    {
        if (scores == null || scores.Length == 0)
        {
            throw new ArgumentException("Не удаётся вычислить уверенность ML модели при определении типа угрозы.");
        }

        return scores.Max();
    }

    private static string BuildExplanation(IcsThreatType threatType, double confidence)
    {
        string confidenceLevel = confidence switch
        {
            >= 0.9 => "высокой",
            >= 0.7 => "средне-высокой",
            >= 0.5 => "средней",
            _ => "низкой"
        };

        if (threatType == IcsThreatType.None)
        {
            return $"Классификация ML-моделью: угроза не обнаружена (уверенность: {confidence:P0}).";
        }

        return $"Классификация ML-моделью: обнаружена угроза {threatType} с {confidenceLevel} уверенностью ({confidence:P0}).";
    }

    private static MlTrainingData ConvertToMlData(SensorReading reading)
    {
        var features = reading.Features;
        return new MlTrainingData
        {
            AveragePacketSize = features.AveragePacketSize,
            SuspiciousCommandCount = features.SuspiciousCommandCount,
            FailedLoginRate = features.FailedLoginRate,
            TrafficToEngineeringStationsRatio = features.TrafficToEngineeringStationsRatio,
            PlcConfigChangeRate = features.PlcConfigChangeRate,
            HmiScreenChangeRate = features.HmiScreenChangeRate,
            EncryptedTrafficRatio = features.EncryptedTrafficRatio,
            ExternalConnectionCount = features.ExternalConnectionCount,
            BroadcastTrafficRatio = features.BroadcastTrafficRatio,
            ProtocolViolationScore = features.ProtocolViolationScore,
            DataExfiltrationVolume = features.DataExfiltrationVolume,
            CpuLoadAnomalyScore = features.CpuLoadAnomalyScore,
            ProcessValueAnomalyScore = features.ProcessValueAnomalyScore,
            ConnectionRate = features.ConnectionRate,
            DistinctProtocolCount = features.DistinctProtocolCount
        };
    }
}
