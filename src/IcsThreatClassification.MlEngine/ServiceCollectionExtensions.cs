using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.MlEngine.Data;
using IcsThreatClassification.MlEngine.Inference;
using IcsThreatClassification.MlEngine.Training;
using Microsoft.Extensions.DependencyInjection;

namespace IcsThreatClassification.MlEngine;

/// <summary>
/// Методы расширения для регистрации сервисов MlEngine.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMlThreatClassifier(this IServiceCollection services)
    {
        services.AddSingleton<ISyntheticDatasetGenerator, SyntheticDatasetGenerator>();
        services.AddSingleton<ThreatClassificationTrainer>();
        services.AddSingleton<IThreatModelTrainer>(sp => sp.GetRequiredService<ThreatClassificationTrainer>());
        services.AddSingleton<MlThreatClassifier>();
        services.AddSingleton<IMlThreatClassifier>(sp => sp.GetRequiredService<MlThreatClassifier>());

        return services;
    }
}
