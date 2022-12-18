using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;

const string DEFAULT_POLICY = "default";
const string EMAIL_ATTRIBUTE = "email";
const string USERNAME_PARAMETER = "USERNAME";
const string PASSWORD_PARAMETER = "PASSWORD";

var builder = WebApplication.CreateBuilder(args);

// Add AWS Lambda support. When application is run in Lambda Kestrel is swapped out as the web server with Amazon.Lambda.AspNetCoreServer. 
builder.Services.AddAWSLambdaHosting(LambdaEventSource.HttpApi);

builder.Configuration.AddEnvironmentVariables()
    .AddUserSecrets(System.Reflection.Assembly.GetExecutingAssembly(), true);

builder.Services.Configure<AwsJwtOptions>(options => {

    options.AccessKey = builder.Configuration.GetValue<string>(nameof(AwsJwtOptions.AccessKey));
    options.SecretKey = builder.Configuration.GetValue<string>(nameof(AwsJwtOptions.SecretKey));
    options.Authority = builder.Configuration.GetValue<string>(nameof(JwtOptions.Authority));
    options.ClientId = builder.Configuration.GetValue<string>(nameof(JwtOptions.ClientId));

});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {

        options.Authority = builder.Configuration.GetValue<string>(nameof(JwtOptions.Authority));
        options.Audience = builder.Configuration.GetValue<string>(nameof(JwtOptions.ClientId));

    });

builder.Services.AddAuthorization(builder => {
    builder.AddPolicy(DEFAULT_POLICY, pb => {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => {

    // add JWT Authentication
    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "JWT Authentication",
        Description = "Enter JWT Bearer token **_only_**",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer", // must be lower case
        BearerFormat = "JWT",
        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme
        }
    };
    options.AddSecurityDefinition(securityScheme.Reference.Id, securityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { securityScheme, new string[] { } }
    });

});

builder.Services.AddSingleton<IAmazonCognitoIdentityProvider, AmazonCognitoIdentityProviderClient>(services => {

    var jwtOptions = services.GetRequiredService<IOptions<AwsJwtOptions>>();

    var credentials = new Amazon.Runtime.BasicAWSCredentials(
        accessKey: jwtOptions.Value.AccessKey,
        secretKey: jwtOptions.Value.SecretKey
    );

    return new AmazonCognitoIdentityProviderClient(credentials, RegionEndpoint.USWest2);

});

var app = builder.Build();
  
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet(Routes.Root, (IOptions<AwsJwtOptions> jwtOptions) => jwtOptions.Value).AllowAnonymous();

app.MapPost(Routes.Login, async (IOptions<AwsJwtOptions> jwtOptions, 
    IAmazonCognitoIdentityProvider cognito,
    HttpContext ctx,
    UserLogin user) => {

    var request = new AdminInitiateAuthRequest
    {
        UserPoolId = jwtOptions.Value.UserPoolId,
        ClientId = jwtOptions.Value.ClientId,
        AuthFlow = AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
    };

    request.AuthParameters.Add(USERNAME_PARAMETER, user.Username);
    request.AuthParameters.Add(PASSWORD_PARAMETER, user.Password);

    try {
        var response = await cognito.AdminInitiateAuthAsync(request);
        return response.AuthenticationResult.IdToken;
    } catch (NotAuthorizedException ex) {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;  
        return ex.Message;
    } catch (UserNotConfirmedException ex) {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;  
        return ex.Message;
    }

}).AllowAnonymous();

app.MapPost(Routes.Register, async (IOptions<AwsJwtOptions> jwtOptions,
    IAmazonCognitoIdentityProvider cognito,
    HttpContext ctx, 
    UserRegistration user) => {

    var request = new SignUpRequest
    {
        ClientId = jwtOptions.Value.ClientId,
        Password = user.Password,
        Username = user.Username,
    };

    var emailAttribute = new AttributeType
    {
        Name = EMAIL_ATTRIBUTE,
        Value = user.Email
    };
    request.UserAttributes.Add(emailAttribute);

    try {
        var response = await cognito.SignUpAsync(request);
        return response.UserSub;
    } catch (UsernameExistsException ex) {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        return ex.Message;
    } catch (InvalidParameterException ipe) {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        return ipe.Message;
    }

}).AllowAnonymous();

app.MapGet("/secure", () => {


    return "secured!";
}).RequireAuthorization(DEFAULT_POLICY);

app.Run();

public record UserLogin(string Username, string Password);
public record UserRegistration(string Username, string Password, string Email);

public record AwsJwtOptions : JwtOptions 
{
    public string? AccessKey { get; set; }
    public string? SecretKey { get; set; }
    public string? UserPoolId { get { return Authority?.Split('/').Last(); } }
}

public record JwtOptions 
{
    public string? Authority { get; set; }
    public string? ClientId { get; set; }
}

public static class Routes
{
    public const string Root = "/";
    public const string Login = "/login";
    public const string Register = "/register";
}
