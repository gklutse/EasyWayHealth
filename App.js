import * as React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { createDrawerNavigator } from '@react-navigation/drawer';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import SplashScreen from './screens/SplashScreen';
import LoginScreen from './screens/LoginScreen';
import SignUpScreen from './screens/SignUpScreen';
import HomeScreen from './screens/HomeScreen';
import AmbulanceServiceScreen from './screens/AmbulanceServiceScreen';
import DoctorAppointmentsScreen from './screens/DoctorAppointmentsScreen';
import JobBoardScreen from './screens/JobBoardScreen';
import HealthcareRequestsScreen from './screens/HealthcareRequestsScreen';
import ProfileScreen from './screens/ProfileScreen';
import SettingsScreen from './screens/SettingsScreen';
import ForgotPasswordScreen from './screens/ForgotPasswordScreen';
import PasswordResetScreen from './screens/PasswordResetScreen';
import NotificationsScreen from './screens/NotificationsScreen';

const Stack = createStackNavigator();
const Drawer = createDrawerNavigator();

function HomeDrawer() {
  return (
    <Drawer.Navigator initialRouteName="Home">
      <Drawer.Screen name="Home" component={HomeScreen} />
      <Drawer.Screen name="AmbulanceService" component={AmbulanceServiceScreen} />
      <Drawer.Screen name="DoctorAppointments" component={DoctorAppointmentsScreen} />
      <Drawer.Screen name="JobBoard" component={JobBoardScreen} />
      <Drawer.Screen name="HealthcareRequests" component={HealthcareRequestsScreen} />
      <Drawer.Screen name="Profile" component={ProfileScreen} />
      <Drawer.Screen name="Notifications" component={NotificationsScreen} />
      <Drawer.Screen name="Settings" component={SettingsScreen} />
    </Drawer.Navigator>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <NavigationContainer>
        <Stack.Navigator initialRouteName="Splash" screenOptions={{ headerShown: false }}>
          <Stack.Screen name="Splash" component={SplashScreen} />
          <Stack.Screen name="Login" component={LoginScreen} />
          <Stack.Screen name="SignUp" component={SignUpScreen} />
          <Stack.Screen name="ForgotPassword" component={ForgotPasswordScreen} />
          <Stack.Screen name="PasswordReset" component={PasswordResetScreen} />
          <Stack.Screen name="HomeDrawer" component={HomeDrawer} />
        </Stack.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
