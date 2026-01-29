using IcsThreatClassification.Domain.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace IcsThreatClassification.ClassicEngine;

/// <summary>
/// Методы расширения для регистрации сервисов ClassicEngine.
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddClassicThreatClassifier(this IServiceCollection services)
    {
        services.AddSingleton<IClassicThreatClassifier, ClassicThreatClassifier>();
        return services;
    }
}
