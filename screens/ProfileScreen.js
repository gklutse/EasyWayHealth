// screens/ProfileScreen.js
import React from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

export default function ProfileScreen({ navigation }) {
  const handleLogout = () => {
    // Implement logout logic here
    navigation.replace('Login');
  };

  return (
    <View style={styles.container}>
      <Text>User Profile</Text>
      {/* Display user details here */}
      <Button title="Edit Profile" onPress={() => navigation.navigate('Settings')} />
      <Button title="Logout" onPress={handleLogout} />
      <Button title="Back" onPress={() => navigation.goBack()} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: 16,
  },
});
