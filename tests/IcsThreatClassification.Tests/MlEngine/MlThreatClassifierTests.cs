using FluentAssertions;
using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Entities;
using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.Domain.ValueObjects;
using IcsThreatClassification.MlEngine.Data;
using IcsThreatClassification.MlEngine.Inference;
using IcsThreatClassification.MlEngine.Training;
using Xunit;

namespace IcsThreatClassification.Tests.MlEngine;

public sealed class MlThreatClassifierTests
{
    private readonly SyntheticDatasetGenerator _datasetGenerator = new();

    [Fact]
    public void Classify_WithoutLoadedModel_ThrowsInvalidOperationException()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var classifier = new MlThreatClassifier(trainer);

        var features = new SensorFeatureVector();
        var reading = SensorReading.Create(SensorId.NewId(), features);

        var action = () => classifier.Classify(reading);

        action.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void IsModelLoaded_BeforeTraining_ReturnsFalse()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var classifier = new MlThreatClassifier(trainer);

        classifier.IsModelLoaded.Should().BeFalse();
    }

    [Fact]
    public void IsModelLoaded_AfterTraining_ReturnsTrue()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var classifier = new MlThreatClassifier(trainer);

        var dataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 50,
            Seed = 42
        });

        trainer.Train(dataset, ThreatModelTrainingOptions.Default);

        classifier.IsModelLoaded.Should().BeTrue();
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
    public void Classify_TrainedModel_ClassifiesAllThreatTypes(IcsThreatType expectedThreatType)
    {
        var trainer = new ThreatClassificationTrainer(42);
        var classifier = new MlThreatClassifier(trainer);

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
            SamplesPerThreatType = 10,
            Seed = 123
        });

        var testSamples = testDataset.Where(s => s.Label == expectedThreatType).ToList();
        int correctCount = 0;

        foreach (var sample in testSamples)
        {
            var reading = SensorReading.Create(SensorId.NewId(), sample.Features);
            var result = classifier.Classify(reading);

            if (result.ThreatType == expectedThreatType)
            {
                correctCount++;
            }
        }

        double accuracy = (double)correctCount / testSamples.Count;
        accuracy.Should().BeGreaterThanOrEqualTo(0.5,
            $"Т.к. {expectedThreatType} должен корректно классифицироваться как минимум в 50% случаев");
    }

    [Fact]
    public void Classify_ReturnsConfidenceInValidRange()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var classifier = new MlThreatClassifier(trainer);

        var dataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 100,
            Seed = 42
        });

        trainer.Train(dataset, ThreatModelTrainingOptions.Default);

        foreach (var sample in dataset.Take(50))
        {
            var reading = SensorReading.Create(SensorId.NewId(), sample.Features);
            var result = classifier.Classify(reading);

            result.Confidence.Should().BeInRange(0.0, 1.0);
        }
    }

    [Fact]
    public void Classify_ReturnsNonEmptyExplanation()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var classifier = new MlThreatClassifier(trainer);

        var dataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 100,
            Seed = 42
        });

        trainer.Train(dataset, ThreatModelTrainingOptions.Default);

        var sample = dataset.First();
        var reading = SensorReading.Create(SensorId.NewId(), sample.Features);
        var result = classifier.Classify(reading);

        result.Explanation.Should().NotBeNullOrWhiteSpace();
        result.Explanation.Should().Contain("Классификация ML-моделью");
    }
}
