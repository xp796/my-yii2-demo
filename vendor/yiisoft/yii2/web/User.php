<?php
/**
 * @link http://www.yiiframework.com/
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\web;

use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\base\InvalidValueException;
use yii\rbac\CheckAccessInterface;

/**
 * User is the class for the `user` application component that manages the user authentication status.
 *
 * You may use [[isGuest]] to determine whether the current user is a guest or not.
 * If the user is a guest, the [[identity]] property would return `null`. Otherwise, it would
 * be an instance of [[IdentityInterface]].
 *
 * You may call various methods to change the user authentication status:
 *
 * - [[login()]]: sets the specified identity and remembers the authentication status in session and cookie;
 * - [[logout()]]: marks the user as a guest and clears the relevant（相关的、有关的） information from session and cookie;
 * - [[setIdentity()]]: changes the user identity without touching session or cookie
 *   (this is best used in stateless RESTful API implementation).
 *
 * Note that User only maintains（维持、保持） the user authentication status. It does NOT handle how to authenticate
 * a user. The logic of how to authenticate a user should be done in the class implementing [[IdentityInterface]].
 * You are also required to set [[identityClass]] with the name of this class.
 *
 * User is configured as an application component in [[\yii\web\Application]] by default.
 * You can access that instance via `Yii::$app->user`.
 *
 * You can modify its configuration by adding an array to your application config under `components`
 * as it is shown in the following example:
 *
 * ```php
 * 'user' => [
 *     'identityClass' => 'app\models\User', // User must implement the IdentityInterface
 *     'enableAutoLogin' => true,
 *     // 'loginUrl' => ['user/login'],
 *     // ...
 * ]
 * ```
 *
 * @property string|integer $id The unique identifier for the user. If `null`, it means the user is a guest.
 * This property is read-only.
 * @property IdentityInterface|null $identity The identity object associated with the currently logged-in
 * user. `null` is returned if the user is not logged in (not authenticated).
 * @property boolean $isGuest Whether the current user is a guest. This property is read-only.
 * @property string $returnUrl The URL that the user should be redirected to after login. Note that the type
 * of this property differs in getter and setter. See [[getReturnUrl()]] and [[setReturnUrl()]] for details.
 *
 * @author Qiang Xue <qiang.xue@gmail.com>
 * @since 2.0
 */
class User extends Component
{
    const EVENT_BEFORE_LOGIN = 'beforeLogin';
    const EVENT_AFTER_LOGIN = 'afterLogin';
    const EVENT_BEFORE_LOGOUT = 'beforeLogout';
    const EVENT_AFTER_LOGOUT = 'afterLogout';

    /**
     * @var string the class name of the [[identity]] object.
     */
    //User must implement the IdentityInterface 必须继承 IdentityInterface 的用户自己定义的User model
    public $identityClass;
    /**
     * @var boolean whether to enable cookie-based login. Defaults to `false`.
     * Note that this property will be ignored if [[enableSession]] is `false`.
     */
    //是否启用基于cooked的登录，当$enableSession为false是会被忽略
    public $enableAutoLogin = false;
    /**
     * @var boolean whether to use session to persist（持续） authentication（认证、身份验证） status across multiple requests.
     * You set this property to be `false` if your application is stateless, which is often the case
     * for RESTful APIs.
     */
    //是否启用基于session的持续验证登录状态
    public $enableSession = true;
    /**
     * @var string|array the URL for login when [[loginRequired()]] is called.
     * If an array is given, [[UrlManager::createUrl()]] will be called to create the corresponding URL.
     * The first element of the array should be the route to the login action, and the rest of
     * the name-value pairs are GET parameters used to construct the login URL. For example,
     *
     * ```php
     * ['site/login', 'ref' => 1]
     * ```
     *
     * If this property is `null`, a 403 HTTP exception will be raised when [[loginRequired()]] is called.
     */
    //默认的登录路径，如果数组有多个参数的话，后面的参数作为键值对为get方法提供参数，如果该属性为null时当调用loginRequired时会抛出403的异常
    public $loginUrl = ['site/login'];
    /**
     * @var array the configuration of the identity cookie. This property is used only when [[enableAutoLogin]] is `true`.
     * @see Cookie
     */
    //登录验证的cookie参数的名称，只有当enableAutoLogin 为true时才会用到，httpOnly参数的意思是cookie不能通过客户端脚本访问
    public $identityCookie = ['name' => '_identity', 'httpOnly' => true];
    /**
     * @var integer the number of seconds in which the user will be logged out automatically if he
     * remains inactive（不活动）. If this property is not set, the user will be logged out after
     * the current session expires (c.f. [[Session::timeout]]).
     * Note that this will not work if [[enableAutoLogin]] is `true`.
     */
    //如果用户多久不活动的话，自动多少秒会退出登录，如果这个属性没有设置，用户会在当前的session有效期结束后自动退出登录状态，这个属性在enableAutoLogin为true时不会有用
    public $authTimeout;
    /**
     * @var CheckAccessInterface The access checker to use for checking access.
     * If not set the application auth manager will be used.
     * @since 2.0.9
     */
    //检查使用权，当未设置该参数时，应用的 auth manager组件会被使用
    public $accessChecker;
    /**
     * @var integer the number of seconds in which the user will be logged out automatically
     * regardless of activity.
     * Note that this will not work if [[enableAutoLogin]] is `true`.
     */
    //无视用户的活跃状态自动退出登录的时间，当enableAutoLogin为true时不会应用
    public $absoluteAuthTimeout;
    /**
     * @var boolean whether to automatically renew the identity cookie each time a page is requested.
     * This property is effective only when [[enableAutoLogin]] is `true`.
     * When this is `false`, the identity cookie will expire after the specified duration since the user
     * is initially logged in. When this is `true`, the identity cookie will expire（期满。终止） after the specified duration
     * since the user visits the site the last time.
     * @see enableAutoLogin
     */
    // 是否重新生成新的cookie ,这个属性只有enableAutoLogin为true时才会有效
    public $autoRenewCookie = true;
    /**
     * @var string the session variable name used to store the value of [[id]].
     */
    //用来存储用户登录 id变量值的变量名称
    public $idParam = '__id';
    /**
     * @var string the session variable name used to store the value of expiration timestamp of the authenticated state.
     * This is used when [[authTimeout]] is set.
     */
    //当authTimeout被设置时，存储维持登录状态的有效时间的session变量名称
    public $authTimeoutParam = '__expire';
    /**
     * @var string the session variable name used to store the value of absolute expiration timestamp of the authenticated state.
     * This is used when [[absoluteAuthTimeout]] is set.
     */
    //当absoluteAuthTimeout被设置时，存储绝对的维持登录的有效时间的session变量名称
    public $absoluteAuthTimeoutParam = '__absoluteExpire';
    /**
     * @var string the session variable name used to store the value of [[returnUrl]].
     */
    // 存储returnUrl值的session变量名称
    public $returnUrlParam = '__returnUrl';
    /**
     * @var array MIME types for which this component should redirect to the [[loginUrl]].
     * @since 2.0.8
     */
    public $acceptableRedirectTypes = ['text/html', 'application/xhtml+xml'];

    private $_access = [];


    /**
     * Initializes the application component.
     */
    //初始化应用组件，判断必要参数是否设置，未设置抛出异常
    public function init()
    {
        parent::init();

        if ($this->identityClass === null) {
            throw new InvalidConfigException('User::identityClass must be set.');
        }
        if ($this->enableAutoLogin && !isset($this->identityCookie['name'])) {
            throw new InvalidConfigException('User::identityCookie must contain the "name" element.');
        }
    }

    private $_identity = false;

    /**
     * Returns the identity object associated with the currently logged-in user.
     * When [[enableSession]] is true, this method may attempt to read the user's authentication data
     * stored in session and reconstruct（重建、修复） the corresponding identity object, if it has not done so before.
     * @param boolean $autoRenew whether to automatically renew authentication status if it has not been done so before.
     * This is only useful when [[enableSession]] is true.
     * @return IdentityInterface|null the identity object associated with the currently logged-in user.
     * `null` is returned if the user is not logged in (not authenticated).
     * @see login()
     * @see logout()
     */
    //返回自己定义的继承IdentityInterface 的当前登录的用户User对象
    public function getIdentity($autoRenew = true)
    {
        if ($this->_identity === false) {
            if ($this->enableSession && $autoRenew) {
                $this->_identity = null;
                $this->renewAuthStatus();
            } else {
                return null;
            }
        }

        return $this->_identity;
    }

    /**
     * Sets the user identity object.
     *
     * Note that this method does not deal with session or cookie. You should usually use [[switchIdentity()]]
     * to change the identity of the current user.
     *
     * @param IdentityInterface|null $identity the identity object associated with the currently logged user.
     * If null, it means the current user will be a guest without any associated identity.
     * @throws InvalidValueException if `$identity` object does not implement [[IdentityInterface]].
     */
    //设置用户验证对象
    public function setIdentity($identity)
    {
        if ($identity instanceof IdentityInterface) {
            $this->_identity = $identity;
            $this->_access = [];
        } elseif ($identity === null) {
            $this->_identity = null;
        } else {
            throw new InvalidValueException('The identity object must implement IdentityInterface.');
        }
    }

    /**
     * Logs in a user.
     *
     * After logging in a user, you may obtain the user's identity information from the [[identity]] property.从identity属性获取用户的identity信息
     * If [[enableSession]] is true, you may even get the identity information in the next requests without
     * calling this method again.如果enableSession为true时可以不用调用该方法自动获取验证登录信息在下一次请求中
     *
     * The login status is maintained according to the `$duration` parameter:
     *
     * - `$duration == 0`: the identity information will be stored in session and will be available
     *   via [[identity]] as long as the session remains active.
     * - `$duration > 0`: the identity information will be stored in session. If [[enableAutoLogin]] is true,
     *   it will also be stored in a cookie which will expire in `$duration` seconds. As long as
     *   the cookie remains valid or the session is active, you may obtain the user identity information
     *   via [[identity]].
     *
     * Note that if [[enableSession]] is false, the `$duration` parameter will be ignored as it is meaningless
     * in this case.
     *
     * @param IdentityInterface $identity the user identity (which should already be authenticated)
     * @param integer $duration number of seconds that the user can remain in logged-in status.
     * Defaults to 0, meaning login till the user closes the browser or the session is manually destroyed.
     * If greater than 0 and [[enableAutoLogin]] is true, cookie-based login will be supported.
     * Note that if [[enableSession]] is false, this parameter will be ignored.
     * @return boolean whether the user is logged in
     */
    //登录
    public function login(IdentityInterface $identity, $duration = 0)
    {
        //触发self::EVENT_BEFORE_LOGIN 事件
        if ($this->beforeLogin($identity, false, $duration)) {
            //
            $this->switchIdentity($identity, $duration);
            $id = $identity->getId();
            $ip = Yii::$app->getRequest()->getUserIP();
            if ($this->enableSession) {
                $log = "User '$id' logged in from $ip with duration $duration.";
            } else {
                $log = "User '$id' logged in from $ip. Session not enabled.";
            }
            Yii::info($log, __METHOD__);
            //触发self::EVENT_AFTER_LOGIN事件
            $this->afterLogin($identity, false, $duration);
        }

        return !$this->getIsGuest();
    }

    /**
     * Logs in a user by the given access token.
     * This method will first authenticate the user by calling [[IdentityInterface::findIdentityByAccessToken()]]
     * with the provided access token. If successful, it will call [[login()]] to log in the authenticated user.
     * If authentication fails or [[login()]] is unsuccessful, it will return null.
     * @param string $token the access token
     * @param mixed $type the type of the token. The value of this parameter depends on the implementation.
     * For example, [[\yii\filters\auth\HttpBearerAuth]] will set this parameter to be `yii\filters\auth\HttpBearerAuth`.
     * @return IdentityInterface|null the identity associated with the given access token. Null is returned if
     * the access token is invalid or [[login()]] is unsuccessful.
     */
    //通过 access token登录
    public function loginByAccessToken($token, $type = null)
    {
        /* @var $class IdentityInterface */
        $class = $this->identityClass;
        $identity = $class::findIdentityByAccessToken($token, $type);
        if ($identity && $this->login($identity)) {
            return $identity;
        } else {
            return null;
        }
    }

    /**
     * Logs in a user by cookie.
     *
     * This method attempts to log in a user using the ID and authKey information
     * provided by the [[identityCookie|identity cookie]].
     */
    //通过cookie登录
    protected function loginByCookie()
    {
        // 获取登录用的$identity对象 和有效期  return ['identity' => $identity, 'duration' => $duration];
        $data = $this->getIdentityAndDurationFromCookie();
        if (isset($data['identity'], $data['duration'])) {
            $identity = $data['identity'];
            $duration = $data['duration'];
            //触发self::EVENT_BEFORE_LOGIN事件
            if ($this->beforeLogin($identity, true, $duration)) {
                ////为当前用户更新新的identity
                $this->switchIdentity($identity, $this->autoRenewCookie ? $duration : 0);
                //登录用户Id
                $id = $identity->getId();
                //登录用户IP地址
                $ip = Yii::$app->getRequest()->getUserIP();
                //保存日志
                Yii::info("User '$id' logged in from $ip via cookie.", __METHOD__);
                //触发self::EVENT_AFTER_LOGIN事件
                $this->afterLogin($identity, true, $duration);
            }
        }
    }

    /**
     * Logs out the current user.
     * This will remove authentication-related session data.
     * If `$destroySession` is true, all session data will be removed.
     * @param boolean $destroySession whether to destroy the whole session. Defaults to true.
     * This parameter is ignored if [[enableSession]] is false.
     * @return boolean whether the user is logged out
     */
    //当前用户退出登录，会删除验证用户所需的session数据
    public function logout($destroySession = true)
    {
        //获取$identity 当前登录的用户对象
        $identity = $this->getIdentity();
        //触发self::EVENT_BEFORE_LOGOUT事件
        if ($identity !== null && $this->beforeLogout($identity)) {
            //设置_identity为null,删除用户登录是保存的相关cookie session数据
            $this->switchIdentity(null);
            //当前登录用户的id
            $id = $identity->getId();
            //登录用户的IP地址
            $ip = Yii::$app->getRequest()->getUserIP();
            //保存日志
            Yii::info("User '$id' logged out from $ip.", __METHOD__);
            //删除所有session数据
            if ($destroySession && $this->enableSession) {
                Yii::$app->getSession()->destroy();
            }
            //触发self::EVENT_AFTER_LOGOUT事件
            $this->afterLogout($identity);
        }
        //返回是否为游客，也就是是否登录
        return $this->getIsGuest();
    }

    /**
     * Returns a value indicating whether the user is a guest (not authenticated).
     * @return boolean whether the current user is a guest.
     * @see getIdentity()
     */
    //判断是否登录
    public function getIsGuest()
    {
        return $this->getIdentity() === null;
    }

    /**
     * Returns a value that uniquely represents the user.
     * @return string|integer the unique identifier for the user. If `null`, it means the user is a guest.
     * @see getIdentity()
     */
    //返回一个唯一的值代表这个登录的用户
    public function getId()
    {
        $identity = $this->getIdentity();

        return $identity !== null ? $identity->getId() : null;
    }

    /**
     * Returns the URL that the browser should be redirected to after successful login.
     *
     * This method reads the return URL from the session. It is usually used by the login action which
     * may call this method to redirect the browser to where it goes after successful authentication.
     *
     * @param string|array $defaultUrl the default return URL in case it was not set previously.
     * If this is null and the return URL was not set previously, [[Application::homeUrl]] will be redirected to.
     * Please refer to [[setReturnUrl()]] on accepted format of the URL.
     * @return string the URL that the user should be redirected to after login.
     * @see loginRequired()
     */
    //返回浏览器跳转的url当用户成功登录的时候
    public function getReturnUrl($defaultUrl = null)
    {
        //从session中获取 $this->returnUrlParam参数的值
        $url = Yii::$app->getSession()->get($this->returnUrlParam, $defaultUrl);
        if (is_array($url)) {
            if (isset($url[0])) {
                //创建Url
                return Yii::$app->getUrlManager()->createUrl($url);
            } else {
                $url = null;
            }
        }
        //如果url为空的话返回Yii::$app->getHomeUrl()，不为空返回上一步创建的url
        return $url === null ? Yii::$app->getHomeUrl() : $url;
    }

    /**
     * Remembers the URL in the session so that it can be retrieved（重新取回、恢复） back later by [[getReturnUrl()]].
     * @param string|array $url the URL that the user should be redirected to after login.
     * If an array is given, [[UrlManager::createUrl()]] will be called to create the corresponding URL.
     * The first element of the array should be the route, and the rest of
     * the name-value pairs are GET parameters used to construct the URL. For example,
     *
     * ```php
     * ['admin/index', 'ref' => 1]
     * ```
     */
    //设置登录后跳转的Url地址 保存在session中$this->returnUrlParam参数中
    public function setReturnUrl($url)
    {
        Yii::$app->getSession()->set($this->returnUrlParam, $url);
    }

    /**
     * Redirects the user browser to the login page.
     *
     * Before the redirection, the current URL (if it's not an AJAX url) will be kept as [[returnUrl]] so that
     * the user browser may be redirected back to the current page after successful login.
     *
     * Make sure you set [[loginUrl]] so that the user browser can be redirected to the specified login URL after
     * calling this method.
     *
     * Note that when [[loginUrl]] is set, calling this method will NOT terminate the application execution.
     *
     * @param boolean $checkAjax whether to check if the request is an AJAX request. When this is true and the request
     * is an AJAX request, the current URL (for AJAX request) will NOT be set as the return URL.
     * @param boolean $checkAcceptHeader whether to check if the request accepts HTML responses. Defaults to `true`. When this is true and
     * the request does not accept HTML responses the current URL will not be SET as the return URL. Also instead of
     * redirecting the user an ForbiddenHttpException is thrown. This parameter is available since version 2.0.8.
     * @return Response the redirection response if [[loginUrl]] is set
     * @throws ForbiddenHttpException the "Access Denied" HTTP exception if [[loginUrl]] is not set or a redirect is
     * not applicable.
     * @see checkAcceptHeader
     */
    public function loginRequired($checkAjax = true, $checkAcceptHeader = true)
    {
        $request = Yii::$app->getRequest();
        //检查用户接受的content types 类型 是否在 loginUrl跳转的Url MIME types 中
        $canRedirect = !$checkAcceptHeader || $this->checkRedirectAcceptable();
        if ($this->enableSession
            && $request->getIsGet()
            && (!$checkAjax || !$request->getIsAjax())
            && $canRedirect
        ) {
            //设置的请求的Url为登录成功后回调的Url保存在session中
            $this->setReturnUrl($request->getUrl());
        }
        if ($this->loginUrl !== null && $canRedirect) {
            $loginUrl = (array) $this->loginUrl;
            if ($loginUrl[0] !== Yii::$app->requestedRoute) {
                return Yii::$app->getResponse()->redirect($this->loginUrl);
            }
        }
        throw new ForbiddenHttpException(Yii::t('yii', 'Login Required'));
    }

    /**
     * This method is called before logging in a user.
     * The default implementation will trigger the [[EVENT_BEFORE_LOGIN]] event.
     * If you override this method, make sure you call the parent implementation
     * so that the event is triggered.
     * @param IdentityInterface $identity the user identity information
     * @param boolean $cookieBased whether the login is cookie-based
     * @param integer $duration number of seconds that the user can remain in logged-in status.
     * If 0, it means login till the user closes the browser or the session is manually destroyed.
     * @return boolean whether the user should continue to be logged in
     */
    protected function beforeLogin($identity, $cookieBased, $duration)
    {
        $event = new UserEvent([
            'identity' => $identity,
            'cookieBased' => $cookieBased,
            'duration' => $duration,
        ]);
        $this->trigger(self::EVENT_BEFORE_LOGIN, $event);

        return $event->isValid;
    }

    /**
     * This method is called after the user is successfully logged in.
     * The default implementation will trigger the [[EVENT_AFTER_LOGIN]] event.
     * If you override this method, make sure you call the parent implementation
     * so that the event is triggered.
     * @param IdentityInterface $identity the user identity information
     * @param boolean $cookieBased whether the login is cookie-based
     * @param integer $duration number of seconds that the user can remain in logged-in status.
     * If 0, it means login till the user closes the browser or the session is manually destroyed.
     */
    protected function afterLogin($identity, $cookieBased, $duration)
    {
        $this->trigger(self::EVENT_AFTER_LOGIN, new UserEvent([
            'identity' => $identity,
            'cookieBased' => $cookieBased,
            'duration' => $duration,
        ]));
    }

    /**
     * This method is invoked when calling [[logout()]] to log out a user.
     * The default implementation will trigger the [[EVENT_BEFORE_LOGOUT]] event.
     * If you override this method, make sure you call the parent implementation
     * so that the event is triggered.
     * @param IdentityInterface $identity the user identity information
     * @return boolean whether the user should continue to be logged out
     */
    protected function beforeLogout($identity)
    {
        $event = new UserEvent([
            'identity' => $identity,
        ]);
        $this->trigger(self::EVENT_BEFORE_LOGOUT, $event);

        return $event->isValid;
    }

    /**
     * This method is invoked right after a user is logged out via [[logout()]].
     * The default implementation will trigger the [[EVENT_AFTER_LOGOUT]] event.
     * If you override this method, make sure you call the parent implementation
     * so that the event is triggered.
     * @param IdentityInterface $identity the user identity information
     */
    protected function afterLogout($identity)
    {
        $this->trigger(self::EVENT_AFTER_LOGOUT, new UserEvent([
            'identity' => $identity,
        ]));
    }

    /**
     * Renews the identity cookie.
     * This method will set the expiration time of the identity cookie to be the current time
     * plus the originally specified cookie duration.
     */
    //更新验证cookie
    protected function renewIdentityCookie()
    {
        $name = $this->identityCookie['name'];
        $value = Yii::$app->getRequest()->getCookies()->getValue($name);
        if ($value !== null) {
            $data = json_decode($value, true);
            if (is_array($data) && isset($data[2])) {
                $cookie = new Cookie($this->identityCookie);
                $cookie->value = $value;
                $cookie->expire = time() + (int) $data[2];
                Yii::$app->getResponse()->getCookies()->add($cookie);
            }
        }
    }

    /**
     * Sends an identity cookie.
     * This method is used when [[enableAutoLogin]] is true.
     * It saves [[id]], [[IdentityInterface::getAuthKey()|auth key]], and the duration of cookie-based login
     * information in the cookie.
     * @param IdentityInterface $identity
     * @param integer $duration number of seconds that the user can remain in logged-in status.
     * @see loginByCookie()
     */
    //增加 identity 验证登录的cookie
    protected function sendIdentityCookie($identity, $duration)
    {
        $cookie = new Cookie($this->identityCookie);
        $cookie->value = json_encode([
            $identity->getId(),
            $identity->getAuthKey(),
            $duration,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $cookie->expire = time() + $duration;
        Yii::$app->getResponse()->getCookies()->add($cookie);
    }

    /**
     * Determines if an identity cookie has a valid format and contains a valid auth key.
     * This method is used when [[enableAutoLogin]] is true.
     * This method attempts to authenticate a user using the information in the identity cookie.
     * @return array|null Returns an array of 'identity' and 'duration' if valid, otherwise null.
     * @see loginByCookie()
     * @since 2.0.9
     */
    //从cookie中获取登录的identity信息 和duration（持续时间）信息  return ['identity' => $identity, 'duration' => $duration];
    protected function getIdentityAndDurationFromCookie()
    {
        $value = Yii::$app->getRequest()->getCookies()->getValue($this->identityCookie['name']);
        if ($value === null) {
            return null;
        }
        $data = json_decode($value, true);
        if (count($data) == 3) {
            list ($id, $authKey, $duration) = $data;
            /* @var $class IdentityInterface */
            $class = $this->identityClass;
            $identity = $class::findIdentity($id);
            if ($identity !== null) {
                if (!$identity instanceof IdentityInterface) {
                    throw new InvalidValueException("$class::findIdentity() must return an object implementing IdentityInterface.");
                } elseif (!$identity->validateAuthKey($authKey)) {
                    Yii::warning("Invalid auth key attempted for user '$id': $authKey", __METHOD__);
                } else {
                    return ['identity' => $identity, 'duration' => $duration];
                }
            }
        }
        //删除登录保存的一些 identity cookie信息
        $this->removeIdentityCookie();
        return null;
    }
     
    /**
     * Removes the identity cookie.
     * This method is used when [[enableAutoLogin]] is true.
     * @since 2.0.9
     */
    //删除登录保存的一些 identity cookie信息
    protected function removeIdentityCookie()
    {
        Yii::$app->getResponse()->getCookies()->remove(new Cookie($this->identityCookie));
    }

    /**
     * Switches to a new identity for the current user.
     *
     * When [[enableSession]] is true, this method may use session and/or cookie to store the user identity information,
     * according to the value of `$duration`. Please refer to [[login()]] for more details.
     *
     * This method is mainly called by [[login()]], [[logout()]] and [[loginByCookie()]]
     * when the current user needs to be associated with the corresponding identity information.
     *
     * @param IdentityInterface|null $identity the identity information to be associated with the current user.
     * If null, it means switching the current user to be a guest.
     * @param integer $duration number of seconds that the user can remain in logged-in status.
     * This parameter is used only when `$identity` is not null.
     */
    //为当前用户更新新的identity
    public function switchIdentity($identity, $duration = 0)
    {
        //设置_identity
        $this->setIdentity($identity);
        //如果enableSession为false直接返回
        if (!$this->enableSession) {
            return;
        }

        /* Ensure any existing identity cookies are removed. */
        //当允许基于cookie的自动登录时，确保存在的identity cookie 已经被删除
        if ($this->enableAutoLogin) {
            $this->removeIdentityCookie();
        }

        $session = Yii::$app->getSession();
        //当前环境不是测试环境时，重新生成
        if (!YII_ENV_TEST) {
            //不修改当前会话中数据的前提下使用新的 ID 替换原有会话 ID。
            $session->regenerateID(true);
        }
        $session->remove($this->idParam);
        $session->remove($this->authTimeoutParam);
        //如果$identity存在，重新设置登录所需的session参数的值
        if ($identity) {
            $session->set($this->idParam, $identity->getId());
            if ($this->authTimeout !== null) {
                $session->set($this->authTimeoutParam, time() + $this->authTimeout);
            }
            if ($this->absoluteAuthTimeout !== null) {
                $session->set($this->absoluteAuthTimeoutParam, time() + $this->absoluteAuthTimeout);
            }
            //如果$duration 大于0 并且允许基于cookie的自动登录，从新保存基于cookie登录所需的cookie数据
            if ($duration > 0 && $this->enableAutoLogin) {
                $this->sendIdentityCookie($identity, $duration);
            }
        }
    }

    /**
     * Updates the authentication status using the information from session and cookie.
     *
     * This method will try to determine the user identity using the [[idParam]] session variable.
     *
     * If [[authTimeout]] is set, this method will refresh the timer.
     *
     * If the user identity cannot be determined by session, this method will try to [[loginByCookie()|login by cookie]]
     * if [[enableAutoLogin]] is true.
     */
    //从session和cookie更新身份验证的状态，
    protected function renewAuthStatus()
    {
        $session = Yii::$app->getSession();
        //$session->getHasSessionId() 返回一个值用来说明当前的请求是否发送了 session ID，默认的用session name会检查cookie和$_GET，如果通过其他途径的话需要重写覆盖此方法，获取session中__id的值
        $id = $session->getHasSessionId() || $session->getIsActive() ? $session->get($this->idParam) : null;

        if ($id === null) {
            $identity = null;
        } else {
            /* @var $class IdentityInterface */
            $class = $this->identityClass;
            $identity = $class::findIdentity($id);
        }

        $this->setIdentity($identity);

        if ($identity !== null && ($this->authTimeout !== null || $this->absoluteAuthTimeout !== null)) {
            $expire = $this->authTimeout !== null ? $session->get($this->authTimeoutParam) : null;
            $expireAbsolute = $this->absoluteAuthTimeout !== null ? $session->get($this->absoluteAuthTimeoutParam) : null;
            if ($expire !== null && $expire < time() || $expireAbsolute !== null && $expireAbsolute < time()) {
                //登录有效时间$expire小于现在时间或者绝对$expireAbsolute小于现在时间，退出登录状态
                $this->logout(false);
            } elseif ($this->authTimeout !== null) {
                //没有超时，重新设置authTimeoutParam 过期时间参数的值
                $session->set($this->authTimeoutParam, time() + $this->authTimeout);
            }
        }
        //允许基于cookie的自动登录
        if ($this->enableAutoLogin) {
            if ($this->getIsGuest()) {
                //如果是游客，用cookie登录
                $this->loginByCookie();
            } elseif ($this->autoRenewCookie) {
                //已登录，重新刷新登录时保存的相关cookie的值
                $this->renewIdentityCookie();
            }
        }
    }

    /**
     * Checks if the user can perform the operation as specified by the given permission.
     *
     * Note that you must configure "authManager" application component in order to use this method.
     * Otherwise it will always return false.
     *
     * @param string $permissionName the name of the permission (e.g. "edit post") that needs access check.
     * @param array $params name-value pairs that would be passed to the rules associated
     * with the roles and permissions assigned to the user.
     * @param boolean $allowCaching whether to allow caching the result of access check.
     * When this parameter is true (default), if the access check of an operation was performed
     * before, its result will be directly returned when calling this method to check the same
     * operation. If this parameter is false, this method will always call
     * [[\yii\rbac\CheckAccessInterface::checkAccess()]] to obtain the up-to-date access result. Note that this
     * caching is effective only within the same request and only works when `$params = []`.
     * @return boolean whether the user can perform the operation as specified by the given permission.
     */
    //检查用户是否有执行指定$permissionName操作的权限
    public function can($permissionName, $params = [], $allowCaching = true)
    {
        //直接从$this->_access 取出
        if ($allowCaching && empty($params) && isset($this->_access[$permissionName])) {
            return $this->_access[$permissionName];
        }
        if (($accessChecker = $this->getAccessChecker()) === null) {
            return false;
        }
        $access = $accessChecker->checkAccess($this->getId(), $permissionName, $params);
        if ($allowCaching && empty($params)) {
            $this->_access[$permissionName] = $access;
        }

        return $access;
    }

    /**
     * Checks if the `Accept` header contains a content type that allows redirection to the login page.
     * The login page is assumed to serve `text/html` or `application/xhtml+xml` by default. You can change acceptable
     * content types by modifying [[acceptableRedirectTypes]] property.
     * @return boolean whether this request may be redirected to the login page.
     * @see acceptableRedirectTypes
     * @since 2.0.8
     */
    //检查用户接受的content types 类型 是否在 loginUrl跳转的Url MIME types 中
    protected function checkRedirectAcceptable()
    {
        //Returns the content types acceptable by the end user 返回用户接受的content types 类型
        $acceptableTypes = Yii::$app->getRequest()->getAcceptableContentTypes();
        // 为空或者为count($acceptableTypes) === 1 && array_keys($acceptableTypes)[0] === '*/*' 返回true
        if (empty($acceptableTypes) || count($acceptableTypes) === 1 && array_keys($acceptableTypes)[0] === '*/*') {
            return true;
        }

        foreach ($acceptableTypes as $type => $params) {
            if (in_array($type, $this->acceptableRedirectTypes, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns auth manager associated with the user component.
     *
     * By default this is the `authManager` application component.
     * You may override this method to return a different auth manager instance if needed.
     * @return \yii\rbac\ManagerInterface
     * @since 2.0.6
     * @deprecated Deprecated since version 2.0.9, to be removed in 2.1. Use `getAccessChecker()` instead.
     */
    //返回和user组件关联的auth manager 组件，默认的是`authManager` 应用组件.
    protected function getAuthManager()
    {
        return Yii::$app->getAuthManager();
    }

    /**
     * Returns the access checker used for checking access.
     * @return CheckAccessInterface
     * @since 2.0.9
     */
    protected function getAccessChecker()
    {
        return $this->accessChecker !== null ? $this->accessChecker : $this->getAuthManager();
    }
}
