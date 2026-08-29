FROM mcr.microsoft.com/dotnet/sdk:8.0 AS builder
WORKDIR /src
COPY services/dotnet-analyzer/ .
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=builder /app .
ENV GRPC_PORT=50057
EXPOSE 50057
ENTRYPOINT ["dotnet", "dotnet-analyzer.dll"]
