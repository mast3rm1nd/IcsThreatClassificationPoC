using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Entities;
using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.Domain.ValueObjects;
using Spectre.Console;

namespace IcsThreatClassification.App.Commands;

/// <summary>
/// Обработчик команды для классификации образцов с использованием обоих классификаторов.
/// </summary>
internal sealed class ClassifySampleCommand
{
    private readonly IClassicThreatClassifier _classicClassifier;
    private readonly IMlThreatClassifier _mlClassifier;
    private readonly IThreatModelTrainer _modelTrainer;
    private readonly ISyntheticDatasetGenerator _datasetGenerator;

    public ClassifySampleCommand(
        IClassicThreatClassifier classicClassifier,
        IMlThreatClassifier mlClassifier,
        IThreatModelTrainer modelTrainer,
        ISyntheticDatasetGenerator datasetGenerator)
    {
        _classicClassifier = classicClassifier;
        _mlClassifier = mlClassifier;
        _modelTrainer = modelTrainer;
        _datasetGenerator = datasetGenerator;
    }

    public void Execute(string modelPath)
    {
        if (!File.Exists(modelPath))
        {
            AnsiConsole.MarkupLine($"[red]Файл модели не найден:[/] {modelPath}");
            AnsiConsole.MarkupLine("[yellow]Сначала выполните команду 'generate-and-train'.[/]");
            return;
        }

        AnsiConsole.MarkupLine($"[bold]Загрузка модели из:[/] {modelPath}");
        _modelTrainer.Load(modelPath);

        var threatTypes = Enum.GetValues<IcsThreatType>();
        var options = new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 1,
            Seed = DateTime.Now.Millisecond
        };

        var samples = _datasetGenerator.Generate(options);

        AnsiConsole.MarkupLine("\n[bold]Сравнение результатов классификации[/]\n");

        var table = new Table();
        table.AddColumn("Ожидается");
        table.AddColumn("Классический");
        table.AddColumn("Увер.");
        table.AddColumn("ML-результат");
        table.AddColumn("Увер.");
        table.AddColumn("Совп.");

        int matchCount = 0;
        int totalCount = 0;

        foreach (var threatType in threatTypes)
        {
            var sample = samples.First(s => s.Label == threatType);
            var reading = SensorReading.Create(SensorId.NewId(), sample.Features);

            var classicResult = _classicClassifier.Classify(reading);
            var mlResult = _mlClassifier.Classify(reading);

            bool classicMatch = classicResult.ThreatType == threatType;
            bool mlMatch = mlResult.ThreatType == threatType;
            bool bothMatch = classicMatch && mlMatch;

            if (bothMatch)
            {
                matchCount++;
            }
            totalCount++;

            string matchIndicator = bothMatch ? "[green]Да[/]" : "[red]Нет[/]";

            table.AddRow(
                threatType.ToString(),
                FormatThreatType(classicResult.ThreatType, classicMatch),
                $"{classicResult.Confidence:P0}",
                FormatThreatType(mlResult.ThreatType, mlMatch),
                $"{mlResult.Confidence:P0}",
                matchIndicator);
        }

        AnsiConsole.Write(table);

        AnsiConsole.MarkupLine($"\n[bold]Согласованность:[/] {matchCount}/{totalCount} ({(double)matchCount / totalCount:P0})");

        DisplayDetailedSample(samples);
    }

    private static string FormatThreatType(IcsThreatType type, bool isCorrect)
    {
        string name = type.ToString();
        return isCorrect ? $"[green]{name}[/]" : $"[red]{name}[/]";
    }

    private void DisplayDetailedSample(IReadOnlyCollection<Domain.Models.LabeledSensorSample> samples)
    {
        AnsiConsole.MarkupLine("\n[bold]Детальная классификация (случайный образец):[/]\n");

        var sample = samples.Skip(new Random().Next(samples.Count)).First();
        var reading = SensorReading.Create(SensorId.NewId(), sample.Features);

        AnsiConsole.MarkupLine($"[bold]Ожидаемая угроза:[/] {sample.Label}");

        var featureTable = new Table();
        featureTable.AddColumn("Признак");
        featureTable.AddColumn("Значение");

        featureTable.AddRow("AveragePacketSize", $"{sample.Features.AveragePacketSize:F1}");
        featureTable.AddRow("SuspiciousCommandCount", sample.Features.SuspiciousCommandCount.ToString(System.Globalization.CultureInfo.InvariantCulture));
        featureTable.AddRow("FailedLoginRate", $"{sample.Features.FailedLoginRate:P1}");
        featureTable.AddRow("TrafficToEngineeringStationsRatio", $"{sample.Features.TrafficToEngineeringStationsRatio:P1}");
        featureTable.AddRow("PlcConfigChangeRate", $"{sample.Features.PlcConfigChangeRate:F2}");
        featureTable.AddRow("HmiScreenChangeRate", $"{sample.Features.HmiScreenChangeRate:F2}");
        featureTable.AddRow("EncryptedTrafficRatio", $"{sample.Features.EncryptedTrafficRatio:P1}");
        featureTable.AddRow("ExternalConnectionCount", sample.Features.ExternalConnectionCount.ToString(System.Globalization.CultureInfo.InvariantCulture));
        featureTable.AddRow("BroadcastTrafficRatio", $"{sample.Features.BroadcastTrafficRatio:P1}");
        featureTable.AddRow("ProtocolViolationScore", $"{sample.Features.ProtocolViolationScore:F2}");
        featureTable.AddRow("DataExfiltrationVolume", $"{sample.Features.DataExfiltrationVolume:F1} MB");
        featureTable.AddRow("CpuLoadAnomalyScore", $"{sample.Features.CpuLoadAnomalyScore:F2}");
        featureTable.AddRow("ProcessValueAnomalyScore", $"{sample.Features.ProcessValueAnomalyScore:F2}");
        featureTable.AddRow("ConnectionRate", $"{sample.Features.ConnectionRate:F1}/s");
        featureTable.AddRow("DistinctProtocolCount", sample.Features.DistinctProtocolCount.ToString(System.Globalization.CultureInfo.InvariantCulture));

        AnsiConsole.Write(featureTable);

        var classicResult = _classicClassifier.Classify(reading);
        var mlResult = _mlClassifier.Classify(reading);

        AnsiConsole.MarkupLine($"\n[bold]Классический классификатор:[/] {classicResult.ThreatType} ({classicResult.Confidence:P0})");
        AnsiConsole.MarkupLine($"[dim]{classicResult.Explanation}[/]");

        AnsiConsole.MarkupLine($"\n[bold]ML-классификатор:[/] {mlResult.ThreatType} ({mlResult.Confidence:P0})");
        AnsiConsole.MarkupLine($"[dim]{mlResult.Explanation}[/]");
    }
}
