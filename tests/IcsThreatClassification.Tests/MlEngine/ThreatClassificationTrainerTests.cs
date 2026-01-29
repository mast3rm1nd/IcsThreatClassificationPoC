using FluentAssertions;
using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.MlEngine.Data;
using IcsThreatClassification.MlEngine.Training;
using Xunit;

namespace IcsThreatClassification.Tests.MlEngine;

public sealed class ThreatClassificationTrainerTests
{
    private readonly SyntheticDatasetGenerator _datasetGenerator = new();

    [Fact]
    public void Train_WithValidDataset_SetsIsModelLoadedToTrue()
    {
        var trainer = new ThreatClassificationTrainer(42);

        var dataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 50,
            Seed = 42
        });

        trainer.Train(dataset, ThreatModelTrainingOptions.Default);

        trainer.IsModelLoaded.Should().BeTrue();
    }

    [Fact]
    public void Train_NullDataset_ThrowsArgumentNullException()
    {
        var trainer = new ThreatClassificationTrainer(42);

        var action = () => trainer.Train(null!, ThreatModelTrainingOptions.Default);

        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Train_NullOptions_ThrowsArgumentNullException()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var dataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 10,
            Seed = 42
        });

        var action = () => trainer.Train(dataset, null!);

        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Save_WithoutTrainedModel_ThrowsInvalidOperationException()
    {
        var trainer = new ThreatClassificationTrainer(42);

        var action = () => trainer.Save("test_model.zip");

        action.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SaveAndLoad_PreservesModel()
    {
        var trainer = new ThreatClassificationTrainer(42);
        var dataset = _datasetGenerator.Generate(new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 100,
            Seed = 42
        });

        trainer.Train(dataset, ThreatModelTrainingOptions.Default);

        string tempPath = Path.Combine(Path.GetTempPath(), $"test_model_{Guid.NewGuid()}.zip");

        try
        {
            trainer.Save(tempPath);
            File.Exists(tempPath).Should().BeTrue();

            var newTrainer = new ThreatClassificationTrainer(42);
            newTrainer.IsModelLoaded.Should().BeFalse();

            newTrainer.Load(tempPath);
            newTrainer.IsModelLoaded.Should().BeTrue();
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    [Fact]
    public void Load_NonExistentFile_ThrowsFileNotFoundException()
    {
        var trainer = new ThreatClassificationTrainer(42);

        var action = () => trainer.Load("nonexistent_model.zip");

        action.Should().Throw<FileNotFoundException>();
    }

    [Fact]
    public void Load_EmptyPath_ThrowsArgumentException()
    {
        var trainer = new ThreatClassificationTrainer(42);

        var action = () => trainer.Load("");

        action.Should().Throw<ArgumentException>();
    }
}
