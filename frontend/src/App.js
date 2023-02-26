import { useState, useEffect } from "react";
import { useDispatch } from "react-redux";
import { fetchCurrentUser } from "./store/session";
import { AuthRoute, ProtectedRoute } from "./components/Routes/Routes";
import { Switch } from "react-router-dom";

import Navigation from "./components/Navigation/Navigation";
import SplashPage from "./components/SplashPage/SplashPage";
import SpotsIndex from "./components/SpotsIndex/SpotsIndex";
import CreateSpotForm from "./components/Spot/CreateSpotForm";
import ShowPage from "./components/ShowPage/ShowPage";
import UserProfile from "./components/UserProfile/UserProfile";

function App() {
	const [loaded, setLoaded] = useState(false);
	const dispatch = useDispatch();
	useEffect(() => {
		dispatch(fetchCurrentUser()).then(() => setLoaded(true));
	}, [dispatch]);

	return (
		loaded && (
			<>
				<Navigation />
				<Switch>
					<AuthRoute exact path="/" component={SplashPage} />

					<AuthRoute exact path="/index" component={SpotsIndex} />
					<AuthRoute
						exact
						path="/spots/:spotId"
						component={ShowPage}
					/>

					<ProtectedRoute
						exact
						path="/spots/create"
						component={CreateSpotForm}
					/>
					<ProtectedRoute
						exact
						path="/users/:userId"
						component={UserProfile}
					/>
				</Switch>
			</>
		)
	);
}

export default App;
