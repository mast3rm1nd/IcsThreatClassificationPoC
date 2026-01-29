using FluentAssertions;
using IcsThreatClassification.ClassicEngine;
using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Entities;
using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.Domain.ValueObjects;
using IcsThreatClassification.MlEngine.Data;
using IcsThreatClassification.MlEngine.Inference;
using IcsThreatClassification.MlEngine.Training;
using Xunit;

namespace IcsThreatClassification.Tests.Integration;

public sealed class ClassifierComparisonTests
{
    private readonly SyntheticDatasetGenerator _datasetGenerator = new();
    private readonly ClassicThreatClassifier _classicClassifier = new();

    [Fact]
    public void BothClassifiers_ClassifyAllThreatTypes_WithReasonableAgreement()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var mlClassifier = new MlThreatClassifier(trainer);

        var trainingDataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 300,
            Seed = 42
        });

        trainer.Train(trainingDataset, new ThreatModelTrainingOptions
        {
            NumberOfIterations = 100,
            Seed = 42
        });

        var testDataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 20,
            Seed = 999
        });

        var threatTypes = Enum.GetValues<IcsThreatType>();
        int totalAgreements = 0;
        int totalSamples = 0;

        foreach (var threatType in threatTypes)
        {
            var samples = testDataset.Where(s => s.Label == threatType).Take(5);

            foreach (var sample in samples)
            {
                var reading = SensorReading.Create(SensorId.NewId(), sample.Features);

                var classicResult = _classicClassifier.Classify(reading);
                var mlResult = mlClassifier.Classify(reading);

                totalSamples++;

                if (classicResult.ThreatType == mlResult.ThreatType)
                {
                    totalAgreements++;
                }
            }
        }

        double agreementRate = (double)totalAgreements / totalSamples;
        agreementRate.Should().BeGreaterThanOrEqualTo(0.3,
            "because classifiers should agree on at least 30% of clear-cut samples");
    }

    [Theory]
    [InlineData(IcsThreatType.UnauthorizedRemoteAccess)]
    [InlineData(IcsThreatType.MaliciousCommandInjection)]
    [InlineData(IcsThreatType.ConfigurationTampering)]
    [InlineData(IcsThreatType.DenialOfService)]
    [InlineData(IcsThreatType.RansomwareActivity)]
    [InlineData(IcsThreatType.DataExfiltration)]
    [InlineData(IcsThreatType.ManInTheMiddle)]
    [InlineData(IcsThreatType.ProtocolMisuse)]
    [InlineData(IcsThreatType.BruteForceAuthentication)]
    [InlineData(IcsThreatType.SuspiciousEngineeringWorkstationActivity)]
    [InlineData(IcsThreatType.None)]
    public void BothClassifiers_HandleAllThreatTypes(IcsThreatType threatType)
    {
        var trainer = new ThreatClassificationTrainer(42);
        var mlClassifier = new MlThreatClassifier(trainer);

        var trainingDataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 200,
            Seed = 42
        });

        trainer.Train(trainingDataset, new ThreatModelTrainingOptions
        {
            NumberOfIterations = 50,
            Seed = 42
        });

        var testDataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 5,
            Seed = 789
        });

        var samples = testDataset.Where(s => s.Label == threatType).ToList();
        samples.Should().NotBeEmpty($"Test samples for {threatType} should exist");

        foreach (var sample in samples)
        {
            var reading = SensorReading.Create(SensorId.NewId(), sample.Features);

            var classicResult = _classicClassifier.Classify(reading);
            var mlResult = mlClassifier.Classify(reading);

            classicResult.Should().NotBeNull();
            mlResult.Should().NotBeNull();

            classicResult.Confidence.Should().BeInRange(0.0, 1.0);
            mlResult.Confidence.Should().BeInRange(0.0, 1.0);

            classicResult.Explanation.Should().NotBeNullOrWhiteSpace();
            mlResult.Explanation.Should().NotBeNullOrWhiteSpace();
        }
    }

    [Fact]
    public void EndToEnd_SimulateSensorDataFlow()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var mlClassifier = new MlThreatClassifier(trainer);

        var dataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 200,
            Seed = 42
        });

        trainer.Train(dataset, ThreatModelTrainingOptions.Default);

        var sensor = Sensor.Create("Substation-Alpha/PLC-001", SensorType.PlcMonitor);

        var readings = new List<SensorReading>
        {
            CreateNormalReading(sensor.Id),
            CreateDosAttackReading(sensor.Id),
            CreateBruteForceReading(sensor.Id)
        };

        foreach (var reading in readings)
        {
            var classicResult = _classicClassifier.Classify(reading);
            var mlResult = mlClassifier.Classify(reading);

            classicResult.Should().NotBeNull();
            mlResult.Should().NotBeNull();
        }
    }

    private static SensorReading CreateNormalReading(SensorId sensorId)
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 250f,
            SuspiciousCommandCount = 0,
            FailedLoginRate = 0.01f,
            TrafficToEngineeringStationsRatio = 0.05f,
            PlcConfigChangeRate = 0.02f,
            HmiScreenChangeRate = 0.03f,
            EncryptedTrafficRatio = 0.02f,
            ExternalConnectionCount = 0,
            BroadcastTrafficRatio = 0.08f,
            ProtocolViolationScore = 0.01f,
            DataExfiltrationVolume = 0.5f,
            CpuLoadAnomalyScore = 0.03f,
            ProcessValueAnomalyScore = 0.02f,
            ConnectionRate = 5f,
            DistinctProtocolCount = 3
        };
        return new SensorReading(DateTimeOffset.UtcNow, sensorId, features);
    }

    private static SensorReading CreateDosAttackReading(SensorId sensorId)
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 1400f,
            SuspiciousCommandCount = 2,
            FailedLoginRate = 0.15f,
            TrafficToEngineeringStationsRatio = 0.1f,
            PlcConfigChangeRate = 0.05f,
            HmiScreenChangeRate = 0.05f,
            EncryptedTrafficRatio = 0.15f,
            ExternalConnectionCount = 5,
            BroadcastTrafficRatio = 0.8f,
            ProtocolViolationScore = 0.3f,
            DataExfiltrationVolume = 2f,
            CpuLoadAnomalyScore = 0.9f,
            ProcessValueAnomalyScore = 0.5f,
            ConnectionRate = 150f,
            DistinctProtocolCount = 3
        };
        return new SensorReading(DateTimeOffset.UtcNow, sensorId, features);
    }

    private static SensorReading CreateBruteForceReading(SensorId sensorId)
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 150f,
            SuspiciousCommandCount = 1,
            FailedLoginRate = 0.85f,
            TrafficToEngineeringStationsRatio = 0.5f,
            PlcConfigChangeRate = 0.05f,
            HmiScreenChangeRate = 0.08f,
            EncryptedTrafficRatio = 0.25f,
            ExternalConnectionCount = 5,
            BroadcastTrafficRatio = 0.08f,
            ProtocolViolationScore = 0.1f,
            DataExfiltrationVolume = 1f,
            CpuLoadAnomalyScore = 0.2f,
            ProcessValueAnomalyScore = 0.1f,
            ConnectionRate = 80f,
            DistinctProtocolCount = 2
        };
        return new SensorReading(DateTimeOffset.UtcNow, sensorId, features);
    }
}
