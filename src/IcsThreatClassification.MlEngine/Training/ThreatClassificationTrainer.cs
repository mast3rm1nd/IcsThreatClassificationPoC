using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Models;
using IcsThreatClassification.Domain.ValueObjects;
using Microsoft.ML;

namespace IcsThreatClassification.MlEngine.Training;

/// <summary>
/// Тренер модели классификации угроз на основе ML.NET.
/// </summary>
public sealed class ThreatClassificationTrainer : IThreatModelTrainer
{
    private readonly MLContext _mlContext;
    private ITransformer? _trainedModel;
    private DataViewSchema? _modelSchema;

    public bool IsModelLoaded => _trainedModel != null;

    public ThreatClassificationTrainer()
    {
        _mlContext = new MLContext();
    }

    public ThreatClassificationTrainer(int? seed)
    {
        _mlContext = seed.HasValue ? new MLContext(seed.Value) : new MLContext();
    }

    public void Train(IEnumerable<LabeledSensorSample> dataset, ThreatModelTrainingOptions options)
    {
        ArgumentNullException.ThrowIfNull(dataset);
        ArgumentNullException.ThrowIfNull(options);

        var trainingData = ConvertToMlData(dataset);
        var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);

        var pipeline = BuildPipeline(options);

        _trainedModel = pipeline.Fit(dataView);
        _modelSchema = dataView.Schema;
    }

    public void Save(string path)
    {
        if (_trainedModel == null || _modelSchema == null)
        {
            throw new InvalidOperationException("Обученная модель недоступна. Сначала вызовите Train().");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _mlContext.Model.Save(_trainedModel, _modelSchema, path);
    }

    public void Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Файл модели не найден: {path}");
        }

        _trainedModel = _mlContext.Model.Load(path, out _modelSchema);
    }

    internal ITransformer? GetTrainedModel() => _trainedModel;

    internal MLContext GetMlContext() => _mlContext;

    private Microsoft.ML.Data.EstimatorChain<Microsoft.ML.Transforms.KeyToValueMappingTransformer> BuildPipeline(ThreatModelTrainingOptions options)
    {
        var featureColumns = SensorFeatureVector.FeatureNames;

        var dataProcessPipeline = _mlContext.Transforms.Concatenate("Features", featureColumns)
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.Transforms.Conversion.MapValueToKey("Label"))
            .AppendCacheCheckpoint(_mlContext);

        if (options.UseGpu)
        {
            // LightGBM с настройками GPU
            var trainer = _mlContext.MulticlassClassification.Trainers.LightGbm(
                labelColumnName: "Label",
                featureColumnName: "Features",
                numberOfIterations: options.NumberOfIterations,
                learningRate: options.LearningRate);

            return dataProcessPipeline
                .Append(trainer)
                .Append(_mlContext.Transforms.Conversion.MapKeyToValue("PredictedLabel"));
        }
        else
        {
            // SDCA для обучения на CPU
            var trainer = _mlContext.MulticlassClassification.Trainers.SdcaMaximumEntropy(
                labelColumnName: "Label",
                featureColumnName: "Features",
                maximumNumberOfIterations: options.NumberOfIterations);

            return dataProcessPipeline
                .Append(trainer)
                .Append(_mlContext.Transforms.Conversion.MapKeyToValue("PredictedLabel"));
        }
    }

    private static IEnumerable<MlTrainingData> ConvertToMlData(IEnumerable<LabeledSensorSample> samples)
    {
        return samples.Select(s => new MlTrainingData
        {
            AveragePacketSize = s.Features.AveragePacketSize,
            SuspiciousCommandCount = s.Features.SuspiciousCommandCount,
            FailedLoginRate = s.Features.FailedLoginRate,
            TrafficToEngineeringStationsRatio = s.Features.TrafficToEngineeringStationsRatio,
            PlcConfigChangeRate = s.Features.PlcConfigChangeRate,
            HmiScreenChangeRate = s.Features.HmiScreenChangeRate,
            EncryptedTrafficRatio = s.Features.EncryptedTrafficRatio,
            ExternalConnectionCount = s.Features.ExternalConnectionCount,
            BroadcastTrafficRatio = s.Features.BroadcastTrafficRatio,
            ProtocolViolationScore = s.Features.ProtocolViolationScore,
            DataExfiltrationVolume = s.Features.DataExfiltrationVolume,
            CpuLoadAnomalyScore = s.Features.CpuLoadAnomalyScore,
            ProcessValueAnomalyScore = s.Features.ProcessValueAnomalyScore,
            ConnectionRate = s.Features.ConnectionRate,
            DistinctProtocolCount = s.Features.DistinctProtocolCount,
            Label = (uint)s.Label
        });
    }
}
