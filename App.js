// App.js
import * as React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import LoginScreen from './screens/LoginScreen';
import SignUpScreen from './screens/SignUpScreen';
import LandingScreen from './screens/LandingScreen';
import AmbulanceRequestScreen from './screens/AmbulanceRequestScreen';
import DoctorAppointmentScreen from './screens/DoctorAppointmentScreen';
import JobPostingScreen from './screens/JobPostingScreen';

const Stack = createStackNavigator();

export default function App() {
  return (
    <SafeAreaProvider>
      <NavigationContainer>
        <Stack.Navigator initialRouteName="SignUp">
          <Stack.Screen name="Login" component={LoginScreen} />
          <Stack.Screen name="SignUp" component={SignUpScreen} />
          <Stack.Screen name="Landing" component={LandingScreen} />
          <Stack.Screen name="AmbulanceRequest" component={AmbulanceRequestScreen} />
          <Stack.Screen name="DoctorAppointment" component={DoctorAppointmentScreen} />
          <Stack.Screen name="JobPosting" component={JobPostingScreen} />
        </Stack.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
