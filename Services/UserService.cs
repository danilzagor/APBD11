using JWT.Controllers;
using JWT.Extensions;

namespace JWT.Services;
public interface IUserService
{
    public void AddUser(AuthController.UserInDatabase user);
    public AuthController.UserInDatabase GetUser(string userName);
    public bool DoesUserExist(string userName);
}
public class UserService:IUserService
{
    private List<AuthController.UserInDatabase> _database = []; 
    public void AddUser(AuthController.UserInDatabase user)
    {
        _database.Add(user);
    }

    public AuthController.UserInDatabase GetUser(string userName)
    {
        var res = _database.FirstOrDefault(database => database.Login == userName);
        if (res is null)
        {
            throw new NotFoundException($"User with username:{userName} doesn't exist");
        }

        return res;
    }
    public bool DoesUserExist(string userName)
    {
        var res = _database.FirstOrDefault(database => database.Login == userName);
        return res is not null;
    }
}